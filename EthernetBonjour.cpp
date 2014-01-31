//  Copyright (C) 2010 Georg Kaindl
//  http://gkaindl.com
//
//  This file is part of Arduino EthernetBonjour.
//
//  EthernetBonjour is free software: you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version.
//
//  EthernetBonjour is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with EthernetBonjour. If not, see
//  <http://www.gnu.org/licenses/>.
//

#define  HAS_SERVICE_REGISTRATION      1  // disabling saves about 1.25 kilobytes
#define  HAS_NAME_BROWSING             0  // disable together with above, additionally saves about 4.3 kilobytes

#include <string.h>
#include <stdlib.h>
#include <Arduino.h>
#include <Ethernet.h>
#include <util.h>
// We cant use the predefined macros directly, because we have to cast to uint16_t / uint32_t before!
#define htons_(x) htons((uint16_t)x)
#define ntohs_(x) htons_(x)

#define htonl_(x) htonl((uint32_t)x)
#define ntohl_(x) htonl_(x)

#include <utility/w5100.h>

#include "EthernetBonjour.h"

#define  MDNS_DEFAULT_NAME       "arduino"
#define  MDNS_TLD                ".local"
#define  DNS_SD_SERVICE          "_services._dns-sd._udp.local"
#define  MDNS_SERVER_PORT        (5353)
#define  MDNS_NQUERY_RESEND_TIME (1000)   // 1 second, name query re-send timeout
#define  MDNS_SQUERY_RESEND_TIME (10000)  // 10 seconds, service query re-send timeout
#define  MDNS_RESPONSE_TTL       (120)    // two minutes (in seconds)

#define  MDNS_MAX_SERVICES_PER_PACKET  (6)


#if defined(W5200)
  #define MAX_SOCK_NUM 8
#else
  #define MAX_SOCK_NUM 4
#endif


#define  _BROKEN_MALLOC_   1
#undef _USE_MALLOC_

static uint8_t mdnsMulticastIPAddr[] = { 224, 0, 0, 251 };
static uint8_t mdnsHWAddr[] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb };

typedef enum _MDNSPacketType_t {
   MDNSPacketTypeMyIPAnswer,
   MDNSPacketTypeNoIPv6AddrAvailable,
   MDNSPacketTypeServiceRecord,
   MDNSPacketTypeServiceRecordRelease,
   MDNSPacketTypeNameQuery,
   MDNSPacketTypeServiceQuery,
} MDNSPacketType_t;

typedef struct _DNSHeader_t {
   uint16_t    xid;
   uint8_t     recursionDesired:1;
   uint8_t     truncated:1;
   uint8_t     authoritiveAnswer:1;
   uint8_t     opCode:4;
   uint8_t     queryResponse:1;
   uint8_t     responseCode:4;
   uint8_t     checkingDisabled:1;
   uint8_t     authenticatedData:1;
   uint8_t     zReserved:1;
   uint8_t     recursionAvailable:1;
   uint16_t    queryCount;
   uint16_t    answerCount;
   uint16_t    authorityCount;
   uint16_t    additionalCount;
} __attribute__((__packed__)) DNSHeader_t;

typedef enum _DNSOpCode_t {
   DNSOpQuery     = 0,
   DNSOpIQuery    = 1,
   DNSOpStatus    = 2,
   DNSOpNotify    = 4,
   DNSOpUpdate    = 5
} DNSOpCode_t;



// for some reason, I get data corruption issues with normal malloc() on arduino 0017
void* my_malloc(unsigned s)
{
#if defined(_BROKEN_MALLOC_)
   char* b = (char*)malloc(s+2);
   if (b)
      b++;
   
   return (void*)b;
#else
   return malloc(s);
#endif
}

void my_free(void* ptr)
{
#if defined(_BROKEN_MALLOC_)
   char* b = (char*)ptr;
   if (b)
      b--;
   
   free(b);
#else
   free(ptr);
#endif
}

EthernetBonjourClass::EthernetBonjourClass()
{
   memset(&this->_mdnsData, 0, sizeof(MDNSDataInternal_t));
   memset(&this->_serviceRecords, 0, sizeof(this->_serviceRecords));
   
   this->_state = MDNSStateIdle;
   
   this->_bonjourName = NULL;
   this->_resolveNames[0] = NULL;
   this->_resolveNames[1] = NULL;
   
   this->_lastAnnounceMillis = 0;
}

EthernetBonjourClass::~EthernetBonjourClass()
{
   (void)this->_closeMDNSSession();
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::begin(const char* bonjourName)
{
   int statusCode = 0;
   statusCode = this->setBonjourName(bonjourName);
   if (statusCode)
      statusCode = this->_startMDNSSession();
   
   return statusCode;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::begin()
{
   return this->begin(MDNS_DEFAULT_NAME);
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::_initQuery(uint8_t idx, const char* name, unsigned long timeout)
{
   int statusCode = 0;
   
   if (NULL == this->_resolveNames[idx] && NULL != ((0==idx) ? (void*)this->_nameFoundCallback :
                                                               (void*)this->_serviceFoundCallback)) {
      this->_resolveNames[idx] = (uint8_t*)name;
      
      if (timeout)
         this->_resolveTimeouts[idx] = millis() + timeout;
      else
         this->_resolveTimeouts[idx] = 0;
      
      statusCode = (MDNSSuccess == this->_sendMDNSMessage(0,
                                             0,
                                             (idx == 0) ? MDNSPacketTypeNameQuery :
                                                          MDNSPacketTypeServiceQuery,
                                             0));
   } else
      my_free((void*)name);
   
   return statusCode;
}

void EthernetBonjourClass::_cancelQuery(uint8_t idx)
{
   if (NULL != this->_resolveNames[idx]) {
      my_free(this->_resolveNames[idx]);
      this->_resolveNames[idx] = NULL;
   }
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::resolveName(const char* name, unsigned long timeout)
{   
   this->cancelResolveName();
   
   char* n = (char*)my_malloc(strlen(name) + 7);
   if (NULL == n)
      return 0;
   
   strcpy(n, name);
   strcat(n, MDNS_TLD);
         
   return this->_initQuery(0, n, timeout);
}

void EthernetBonjourClass::setNameResolvedCallback(BonjourNameFoundCallback newCallback)
{
   this->_nameFoundCallback = newCallback;
}

void EthernetBonjourClass::cancelResolveName()
{
   this->_cancelQuery(0);
}

int EthernetBonjourClass::isResolvingName()
{
   return (NULL != this->_resolveNames[0]);
}

void EthernetBonjourClass::setServiceFoundCallback(BonjourServiceFoundCallback newCallback)
{
   this->_serviceFoundCallback = newCallback;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::startDiscoveringService(const char* serviceName,
                                                  MDNSServiceProtocol_t proto,
                                                  unsigned long timeout)
{   
   this->stopDiscoveringService();
   
   char* n = (char*)my_malloc(strlen(serviceName) + 13);
   if (NULL == n)
      return 0;
   
   strcpy(n, serviceName);   
         
   const uint8_t* srv_type = this->_postfixForProtocol(proto);
   if (srv_type)
      strcat(n, (const char*)srv_type);
   
   this->_resolveServiceProto = proto;
   
   return this->_initQuery(1, n, timeout);
}

void EthernetBonjourClass::stopDiscoveringService()
{
   this->_cancelQuery(1);
}

int EthernetBonjourClass::isDiscoveringService()
{
   return (NULL != this->_resolveNames[1]);
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::_startMDNSSession()
{
   (void)this->_closeMDNSSession();
      
   if (this->iUdp.beginMulti(mdnsMulticastIPAddr, MDNS_SERVER_PORT) != 1)
      return 0;
   return 1;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::_closeMDNSSession()
{
  this->iUdp.stop();
  return 1;
}

// return value:
// A DNSError_t (DNSSuccess on success, something else otherwise)
// in "int" mode: positive on success, negative on error
MDNSError_t EthernetBonjourClass::_sendMDNSMessage(uint32_t peerAddress, uint32_t xid, int type,
                                                   int serviceRecord)
{
   MDNSError_t statusCode = MDNSSuccess;
   DNSHeader_t dnsHeaderBuf = {0};
   DNSHeader_t* dnsHeader = &dnsHeaderBuf;
   uint8_t* buf;
   
   //memset(dnsHeader, 0, sizeof(DNSHeader_t));
   
   dnsHeader->xid = htons_(xid);
   dnsHeader->opCode = DNSOpQuery;
   
   switch (type) {
      case MDNSPacketTypeServiceRecordRelease:
      case MDNSPacketTypeMyIPAnswer:
         dnsHeader->answerCount = htons_(1);
         dnsHeader->queryResponse = 1;
         dnsHeader->authoritiveAnswer = 1;
         break;
      case MDNSPacketTypeServiceRecord:
         dnsHeader->answerCount = htons_(4);
         dnsHeader->additionalCount = htons_(1);
         dnsHeader->queryResponse = 1;
         dnsHeader->authoritiveAnswer = 1;
         break;
      case MDNSPacketTypeNameQuery:
      case MDNSPacketTypeServiceQuery:
         dnsHeader->queryCount = htons_(1);
         break;
      case MDNSPacketTypeNoIPv6AddrAvailable:
         dnsHeader->queryCount = htons_(1);
         dnsHeader->additionalCount = htons_(1);
         dnsHeader->responseCode = 0x03;
         dnsHeader->authoritiveAnswer = 1;
         dnsHeader->queryResponse = 1;
         break;
   }
   
   iUdp.beginPacket(mdnsMulticastIPAddr, MDNS_SERVER_PORT);
   iUdp.write((uint8_t*)dnsHeader,sizeof(DNSHeader_t));
    
   buf = (uint8_t*)dnsHeader;
   
   // construct the answer section
   switch (type) {
      case MDNSPacketTypeMyIPAnswer: {
         this->_writeMyIPAnswerRecord();
         break;
      }

#if defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION
      
      case MDNSPacketTypeServiceRecord: {

         // SRV location record
         this->_writeServiceRecordName(serviceRecord, 0);
         
         buf[0] = 0x00;
         buf[1] = 0x21;    // SRV record
         buf[2] = 0x80;    // cache flush
         buf[3] = 0x01;    // class IN
         
         // ttl
         *((uint32_t*)&buf[4]) = htonl_(MDNS_RESPONSE_TTL);
         
         // data length
         *((uint16_t*)&buf[8]) = htons_(8 + strlen((char*)this->_bonjourName));
         
         iUdp.write((uint8_t*)buf,10);
         
         // priority and weight
         buf[0] = buf[1] = buf[2] = buf[3] = 0;
         
         // port
         *((uint16_t*)&buf[4]) = htons_(this->_serviceRecords[serviceRecord]->port);
         
         iUdp.write((uint8_t*)buf,6);
         
         // target
         this->_writeDNSName(this->_bonjourName, 1);
         
         // TXT record
         this->_writeServiceRecordName(serviceRecord, 0);
         
         buf[0] = 0x00;
         buf[1] = 0x10;    // TXT record
         buf[2] = 0x80;    // cache flush
         buf[3] = 0x01;    // class IN
         
         // ttl
         *((uint32_t*)&buf[4]) = htonl_(MDNS_RESPONSE_TTL);
         
         iUdp.write((uint8_t*)buf,8);
         
         // data length && text
         if (NULL == this->_serviceRecords[serviceRecord]->textContent) {
            buf[0] = 0x00;
            buf[1] = 0x01;
            buf[2] = 0x00;
            iUdp.write((uint8_t*)buf,3);
         } else {
            int slen = strlen((char*)this->_serviceRecords[serviceRecord]->textContent);
            *((uint16_t*)buf) = htons_(slen);
            iUdp.write((uint8_t*)buf,2);
            iUdp.write((uint8_t*)this->_serviceRecords[serviceRecord]->textContent,slen);
         }
         
         // PTR record (for the dns-sd service in general)
         this->_writeDNSName((const uint8_t*)DNS_SD_SERVICE, 1);
         
         buf[0] = 0x00;
         buf[1] = 0x0c;    // PTR record
         buf[2] = 0x00;    // no cache flush
         buf[3] = 0x01;    // class IN
         
         // ttl
         *((uint32_t*)&buf[4]) = htonl_(MDNS_RESPONSE_TTL);
         
         // data length.
         uint16_t dlen = strlen((char*)this->_serviceRecords[serviceRecord]->servName) + 2;
         *((uint16_t*)&buf[8]) = htons_(dlen);
         
         iUdp.write((uint8_t*)buf,10);
         
         this->_writeServiceRecordName(serviceRecord, 1);
         
         // PTR record (our service)
         this->_writeServiceRecordPTR(serviceRecord,
                                      MDNS_RESPONSE_TTL);
         
         // finally, our IP address as additional record
         this->_writeMyIPAnswerRecord();

         break;
      }
      
      case MDNSPacketTypeServiceRecordRelease: {
         // just send our service PTR with a TTL of zero
         this->_writeServiceRecordPTR(serviceRecord, 0);
         break;
      }
      
#endif // defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION

#if defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING
    
      case MDNSPacketTypeNameQuery:
      case MDNSPacketTypeServiceQuery: 
      {
         // construct a query for the currently set _resolveNames[0]
         this->_writeDNSName(
               (type == MDNSPacketTypeServiceQuery) ? this->_resolveNames[1] :
                                                      this->_resolveNames[0],
               , 1);

         buf[0] = buf[2] = 0x0;
         buf[1] = (type == MDNSPacketTypeServiceQuery) ? 0x0c : 0x01; 
         buf[3] = 0x1;
         iUdp.write((uint8_t*)buf,4);
         
         this->_resolveLastSendMillis[(type == MDNSPacketTypeServiceQuery) ? 1 : 0] = millis();
         
         break;
      }
      
#endif // defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING
      
      case MDNSPacketTypeNoIPv6AddrAvailable: {
         // since the WIZnet doesn't have IPv6, we will respond with a Not Found message
         this->_writeDNSName(this->_bonjourName, 1);
         
         buf[0] = buf[2] = 0x0;
         buf[1] = 0x1c; // AAAA record
         buf[3] = 0x01;
         
         iUdp.write((uint8_t*)buf,4);
         
         // send our IPv4 address record as additional record, in case the peer wants it.
         this->_writeMyIPAnswerRecord();
         
         break;
      }
   }

   iUdp.endPacket();

   return statusCode;
}

// return value:
// A DNSError_t (DNSSuccess on success, something else otherwise)
// in "int" mode: positive on success, negative on error
MDNSError_t EthernetBonjourClass::_processMDNSQuery()
{
   MDNSError_t statusCode = MDNSSuccess;
   DNSHeader_t dnsHeaderBuf;
   DNSHeader_t* dnsHeader = &dnsHeaderBuf;
   int i, j;
   uint8_t* buf;
   uint32_t xid;
   uint16_t ptr, qCnt, aCnt, aaCnt, addCnt;
   uint8_t recordsAskedFor[NumMDNSServiceRecords+2];
   uint8_t recordsFound[2];
   uint8_t wantsIPv6Addr = 0;
   
   memset(recordsAskedFor, 0, sizeof(uint8_t)*(NumMDNSServiceRecords+2));
   memset(recordsFound, 0, sizeof(uint8_t)*2);
   
   if (0 == iUdp.parsePacket()) {
	   statusCode = MDNSTryLater;
       goto errorReturn;
   }
   
   iUdp.read((unsigned char*)dnsHeader, sizeof(DNSHeader_t));
   
   xid = ntohs_(dnsHeader->xid);
   qCnt = ntohs_(dnsHeader->queryCount);
   aCnt = ntohs_(dnsHeader->answerCount);
   aaCnt = ntohs_(dnsHeader->authorityCount);
   addCnt = ntohs_(dnsHeader->additionalCount);

   if (0 == dnsHeader->queryResponse &&
       DNSOpQuery == dnsHeader->opCode &&
       MDNS_SERVER_PORT == iUdp.remotePort()) {
      
      // process an MDNS query
      uint8_t* buf = (uint8_t*)dnsHeader;
      int rLen = 0, tLen = 0;

      // read over the query section 
      for (i=0; i<qCnt; i++) {         
         // construct service name data structures for comparison
         const uint8_t* servNames[NumMDNSServiceRecords+2];
         int servLens[NumMDNSServiceRecords+2];
         uint8_t servNamePos[NumMDNSServiceRecords+2];
         uint8_t servMatches[NumMDNSServiceRecords+2];
         
         // first entry is our own MDNS name, the rest are our services
         servNames[0] = (const uint8_t*)this->_bonjourName;
         servNamePos[0] = 0;
         servLens[0] = strlen((char*)this->_bonjourName);
         servMatches[0] = 1;
         
         // second entry is our own the general DNS-SD service
         servNames[1] = (const uint8_t*)DNS_SD_SERVICE;
         servNamePos[1] = 0;
         servLens[1] = strlen((char*)DNS_SD_SERVICE);
         servMatches[1] = 1;
                  
         for (j=2; j<NumMDNSServiceRecords+2; j++)
            if (NULL != this->_serviceRecords[j-2] && NULL != this->_serviceRecords[j-2]->servName) {
               servNames[j] = this->_serviceRecords[j-2]->servName;
               servLens[j] = strlen((char*)servNames[j]);
               servMatches[j] = 1;
               servNamePos[j] = 0;
            } else {
               servNames[j] = NULL;
               servLens[j] = 0;
               servMatches[j] = 0;
               servNamePos[j] = 0;
            }
   
         tLen = 0;
         do {
            iUdp.read((unsigned char*)buf, 1);
            rLen = buf[0];
            tLen += 1;
            
            if (rLen > 128) {// handle DNS name compression, kinda, sorta            
               iUdp.read((unsigned char*)buf, 1);
               
               for (j=0; j<NumMDNSServiceRecords+2; j++) {
                  if (servNamePos[j] && servNamePos[j] != buf[0]) {
                     servMatches[j] = 0;
                  }
               }
               
               tLen += 1;
            } else if (rLen > 0) {
               int tr = rLen, ir;
               
               while (tr > 0) {
                  ir = (tr > sizeof(DNSHeader_t)) ? sizeof(DNSHeader_t) : tr;
                  
                  iUdp.read((unsigned char*)buf, ir);
                  tr -= ir;
                  
                  for (j=0; j<NumMDNSServiceRecords+2; j++) {
                     if (!recordsAskedFor[j] && servMatches[j])
                        servMatches[j] &= this->_matchStringPart(&servNames[j], &servLens[j], buf,
                                                                 ir);
                  }
               }
               
               tLen += rLen;
            }
         } while (rLen > 0 && rLen <= 128);

         // if this matched a name of ours (and there are no characters left), then
         // check whether this is an A record query (for our own name) or a PTR record query
         // (for one of our services).
         // if so, we'll note to send a record
         iUdp.read((unsigned char*)buf, 4);
         
         for (j=0; j<NumMDNSServiceRecords+2; j++) {
            if (!recordsAskedFor[j] && servNames[j] && servMatches[j] && 0 == servLens[j]) {
               if (0 == servNamePos[j])
                  servNamePos[j] = 4 - tLen;//TODO
               
               if (buf[0] == 0 && buf[3] == 0x01 &&
                  (buf[2] == 0x00 || buf[2] == 0x80)) {
                  
                  if ((0 == j && 0x01 == buf[1]) || (0 < j && (0x0c == buf[1] || 0x10 == buf[1] || 0x21 == buf[1])))
                     recordsAskedFor[j] = 1;
                  else if (0 == j && 0x1c == buf[1])
                     wantsIPv6Addr = 1;
               }
            }
         }
      }
   } 
   
#if (defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION) || (defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING)
   
   else if (1 == dnsHeader->queryResponse &&
              DNSOpQuery == dnsHeader->opCode &&
              MDNS_SERVER_PORT == iUdp.remotePort() &&
              (NULL != this->_resolveNames[0] || NULL != this->_resolveNames[1])) {
         
         int offset = sizeof(DNSHeader_t);
         uint8_t* buf = (uint8_t*)dnsHeader;
         int rLen = 0, tLen = 0;
         
         uint8_t* ptrNames[MDNS_MAX_SERVICES_PER_PACKET];
         uint16_t ptrOffsets[MDNS_MAX_SERVICES_PER_PACKET];
         uint16_t ptrPorts[MDNS_MAX_SERVICES_PER_PACKET];
         uint8_t ptrIPs[MDNS_MAX_SERVICES_PER_PACKET];
         uint8_t servIPs[MDNS_MAX_SERVICES_PER_PACKET][5];
         uint8_t* servTxt[MDNS_MAX_SERVICES_PER_PACKET];
         memset(servIPs, 0, sizeof(uint8_t)*MDNS_MAX_SERVICES_PER_PACKET*5);
         memset(servTxt, 0, sizeof(uint8_t*)*MDNS_MAX_SERVICES_PER_PACKET);
         
         const uint8_t* ptrNamesCmp[MDNS_MAX_SERVICES_PER_PACKET];
         int ptrLensCmp[MDNS_MAX_SERVICES_PER_PACKET];
         uint8_t ptrNamesMatches[MDNS_MAX_SERVICES_PER_PACKET];
         
         uint8_t checkAARecords = 0;
         memset(ptrNames, 0, sizeof(uint8_t*)*MDNS_MAX_SERVICES_PER_PACKET);
         
         const uint8_t* servNames[2];
         uint8_t servNamePos[2];
         int servLens[2];
         uint8_t servMatches[2];
         uint8_t firstNamePtrByte = 0;
         uint8_t partMatched[2];
         uint8_t lastWasCompressed[2];
         uint8_t servWasCompressed[2];
         
         servNamePos[0] = servNamePos[1] = 0;
                  
         for (i=0; i<qCnt+aCnt+aaCnt+addCnt; i++) {

            for (j=0; j<2; j++) {
               if (NULL != this->_resolveNames[j]) {
                  servNames[j] = this->_resolveNames[j];
                  servLens[j] = strlen((const char*)this->_resolveNames[j]);
                  servMatches[j] = 1;
               } else {
                  servNames[j] = NULL;
                  servLens[j] = servMatches[j] = 0;
               }
            }
            
            for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
               if (NULL != ptrNames[j]) {
                  ptrNamesCmp[j] = ptrNames[j];
                  ptrLensCmp[j] = strlen((const char*)ptrNames[j]);
                  ptrNamesMatches[j] = 1;
               }
            }
            
            partMatched[0] = partMatched[1] = 0;
            lastWasCompressed[0] = lastWasCompressed[1] = 0;
            servWasCompressed[0] = servWasCompressed[1] = 0;
            firstNamePtrByte = 0;
            tLen = 0;
                        
            do {
               iUdp.read((unsigned char*)buf, 1);
               rLen = buf[0];
               tLen += 1;
            
               if (rLen > 128) { // handle DNS name compression, kinda, sorta...                         
                  iUdp.read((unsigned char*)buf, 1);

                  for (j=0; j<2; j++) {
                     if (servNamePos[j] && servNamePos[j] != buf[0])
                        servMatches[j] = 0;
                     else
                        servWasCompressed[j] = 1;
                     
                     lastWasCompressed[j] = 1;
                  }
               
                  tLen += 1;
                  
                  if (0 == firstNamePtrByte)
                     firstNamePtrByte = buf[0];
               } else if (rLen > 0) {
                  if (i < qCnt)
                     offset += rLen;
                  else {
                     int tr = rLen, ir;
                     
                     if (0 == firstNamePtrByte)
                        firstNamePtrByte = offset-1; // -1, since we already read length (1 byte)
               
                     while (tr > 0) {
                        ir = (tr > sizeof(DNSHeader_t)) ? sizeof(DNSHeader_t) : tr;
                  
                        iUdp.read((unsigned char*)buf, ir);
                        tr -= ir;
                  
                        for (j=0; j<2; j++) {
                           if (!recordsFound[j] && servMatches[j] && servNames[j])
                              servMatches[j] &= this->_matchStringPart(&servNames[j], &servLens[j],
                                                                       buf, ir);
                              if (!partMatched[j])
                                 partMatched[j] = servMatches[j];
                              
                              lastWasCompressed[j] = 0;
                        }               
                        
                        for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                           if (NULL != ptrNames[j] && ptrNamesMatches[j]) {
                              // only compare the part we have. this is incorrect, but good enough,
                              // since actual MDNS implementations won't go here anyways, as they
                              // should use name compression. This is just so that multiple Arduinos
                              // running this MDNSResponder code should be able to find each other's
                              // services.
                              if (ptrLensCmp[j] >= ir) 
                                 ptrNamesMatches[j] &= this->_matchStringPart(&ptrNamesCmp[j],
                                                            &ptrLensCmp[j], buf, ir);
                           }
                        }
                     }                     
                     
                     tLen += rLen;
                  }
               }
            } while (rLen > 0 && rLen <= 128);
                        
            // if this matched a name of ours (and there are no characters left), then
            // check whether this is an A record query (for our own name) or a PTR record query
            // (for one of our services).
            // if so, we'll note to send a record
            if (i < qCnt)
               offset += 4;
            else if (i >= qCnt) {               
               if (i >= qCnt + aCnt && !checkAARecords)
                  break;
               
               uint8_t packetHandled = 0;
                              
               iUdp.read((unsigned char*)buf, 4);
               
               if (i < qCnt+aCnt) {
                  for (j=0; j<2; j++) {
                     if (0 == servNamePos[j])
                        servNamePos[j] = offset - 4 - tLen;
                                      
                     if (servNames[j] &&
                         ((servMatches[j] && 0 == servLens[j]) ||
                         (partMatched[j] && lastWasCompressed[j]) ||
                         (servWasCompressed[j] && servMatches[j]))) { // somewhat handle compression by guessing
                                             
                        if (buf[0] == 0 && buf[1] == ((0 == j) ? 0x01 : 0x0c) &&
                           (buf[2] == 0x00 || buf[2] == 0x80) && buf[3] == 0x01) {
                           recordsFound[j] = 1;
                        
                           // this is an A or PTR type response. Parse it as such.
                           iUdp.read((unsigned char*)buf, 6);
                        
                           //uint32_t ttl = ntohl_(*(uint32_t*)buf);
                           uint16_t dataLen = ntohs_(*(uint16_t*)&buf[4]);
                        
                           if (0 == j && 4 == dataLen) {
                              // ok, this is the IP address. report it via callback.
                              iUdp.read((unsigned char*)buf, 4);
                              
                              this->_finishedResolvingName((char*)this->_resolveNames[0],
                                                           (const byte*)buf);
                           } else if (1 == j) {
                              uint8_t k;
                              for (k=0; k<MDNS_MAX_SERVICES_PER_PACKET; k++)
                                 if (NULL == ptrNames[k])
                                    break;
                           
                              if (k < MDNS_MAX_SERVICES_PER_PACKET) {
                                 int l = dataLen - 2; // -2: data compression of service postfix
                              
                                 uint8_t* ptrName = (uint8_t*)my_malloc(l);
                              
                                 if (ptrName) {
                                    iUdp.read((unsigned char*)buf, 1);
                                    iUdp.read((unsigned char*)ptrName, l-1);
                                 
                                    if (buf[0] < l-1)
                                       ptrName[buf[0]]; // this catches uncompressed names
                                    else
                                       ptrName[l-1] = '\0';
                                    
                                    ptrNames[k] = ptrName;
                                    ptrOffsets[k] = (uint16_t)(offset);
 
                                    checkAARecords = 1;
                                 }
                              }
                           }
                        
                           //offset += dataLen;
                        
                           packetHandled = 1;
                        }
                     }
                  }
               } else if (i >= qCnt+aCnt+aaCnt) {
                  //  check whether we find a service description
                  if (buf[1] == 0x21) {
                     for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                        if (ptrNames[j] &&
                              ((firstNamePtrByte && firstNamePtrByte == ptrOffsets[j]) ||
                              (0 == ptrLensCmp[j] && ptrNamesMatches[j]))) {
                           // we have found the matching SRV location packet to a previous SRV domain
                           iUdp.read((unsigned char*)buf, 6);
                     
                           //uint32_t ttl = ntohl_(*(uint32_t*)buf);
                           uint16_t dataLen = ntohs_(*(uint16_t*)&buf[4]);

                           if (dataLen >= 8) {
                              iUdp.read((unsigned char*)buf, 8);
                              
                              ptrPorts[j] = ntohs_(*(uint16_t*)&buf[4]);
                              
                              if (buf[6] > 128) { // target is a compressed name
                                 ptrIPs[j] = buf[7];
                              } else { // target is uncompressed
                                 ptrIPs[j] = offset+6;
                              }
                           }
                        
                           offset += dataLen;
                           packetHandled = 1;
                           
                           break;
                        }
                     }
                 } else if (buf[1] == 0x10) { // txt record
                     for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                        if (ptrNames[j] &&
                              ((firstNamePtrByte && firstNamePtrByte == ptrOffsets[j]) ||
                              (0 == ptrLensCmp[j] && ptrNamesMatches[j]))) {
                           
                           iUdp.read((unsigned char*)buf, 6);

                           //uint32_t ttl = ntohl_(*(uint32_t*)buf);
                           uint16_t dataLen = ntohs_(*(uint16_t*)&buf[4]);
                        
                           // if there's a content to this txt record, save it for delivery
                           if (dataLen > 1 && NULL == servTxt[j]) {
                              servTxt[j] = (uint8_t*)my_malloc(dataLen+1);
                              if (NULL != servTxt[j]) {
                                 iUdp.read((unsigned char*)servTxt[j], dataLen);
                              
                                 // zero-terminate
                                 servTxt[j][dataLen] = '\0';
                              }
                           }
                        
                           offset += dataLen;
                           packetHandled = 1;
                        
                           break;
                        }
                     }
                  } else if (buf[1] == 0x01) { // A record (IPv4 address)                     
                     for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                        if (0 == servIPs[j][0]) {
                           servIPs[j][0] = firstNamePtrByte ? firstNamePtrByte : 255;
                     
                           iUdp.read((unsigned char*)buf, 6);
                        
                           uint16_t dataLen = ntohs_(*(uint16_t*)&buf[4]);
                        
                           if (4 == dataLen) {
                              iUdp.read((unsigned char*)&servIPs[j][1], 4);
                           }
                        
                           offset += dataLen;
                           packetHandled = 1;
                           
                           break;
                        }
                     }
                  }
               }
               
               // eat the answer
               if (!packetHandled) {
                  iUdp.read((unsigned char*)buf, 4); // ignore ttl
                  iUdp.read((unsigned char*)buf, 2); // length
                  iUdp.read((unsigned char*)buf, ntohs_(*(uint16_t*)buf)); // skip over content
               }
            }
         }
         
         // deliver the services discovered in this packet
         if (NULL != this->_resolveNames[1]) {
            char* typeName = (char*)this->_resolveNames[1];
            char* p = (char*)this->_resolveNames[1];
            while(*p && *p != '.')
               p++;
            *p = '\0';
            
            for (i=0; i<MDNS_MAX_SERVICES_PER_PACKET; i++)
               if (ptrNames[i]) {
                  const uint8_t* ipAddr = NULL;
                  const uint8_t* fallbackIpAddr = NULL;

                  for (j=0; j<MDNS_MAX_SERVICES_PER_PACKET; j++) {
                     if (servIPs[j][0] == ptrIPs[i] || servIPs[j][0] == 255) {
                        // the || part is such a hack, but it will work as long as there's only
                        // one A record per MDNS packet. fucking DNS name compression.                     
                        ipAddr = &servIPs[j][1];
                        
                        break;
                     } else if (NULL == fallbackIpAddr && 0 != servIPs[j][0])
                        fallbackIpAddr = &servIPs[j][1];
                  }
               
                  // if we can't find a matching IP, we try to use the first one we found.
                  if (NULL == ipAddr) ipAddr = fallbackIpAddr;
               
                  if (ipAddr && this->_serviceFoundCallback) {
                     this->_serviceFoundCallback(typeName,
                                                this->_resolveServiceProto,
                                                (const char*)ptrNames[i],
                                                (const byte*)ipAddr,
                                                (unsigned short)ptrPorts[i],
                                                (const char*)servTxt[i]);
                  }
               }
            *p = '.';
         }
   
         uint8_t k;
         for (k=0; k<MDNS_MAX_SERVICES_PER_PACKET; k++)
            if (NULL != ptrNames[k]) {
               my_free(ptrNames[k]);
               if (NULL != servTxt[k])
                  my_free(servTxt[k]);
            }
   }

#endif // (defined(HAS_SERVICE_REGISTRATION) && HAS_SERVICE_REGISTRATION) || (defined(HAS_NAME_BROWSING) && HAS_NAME_BROWSING)

iUdp.flush();

errorReturn:
   
   // now, handle the requests
   for (j=0; j<NumMDNSServiceRecords+2; j++) {
      if (recordsAskedFor[j]) {
         if (0 == j)
            (void)this->_sendMDNSMessage(iUdp.remoteIP(), xid, (int)MDNSPacketTypeMyIPAnswer, 0);
         else if (1 == j) {
            uint8_t k = 2;
            for (k=0; k<NumMDNSServiceRecords; k++)
               recordsAskedFor[k+2] = 1;
         } else if (NULL != this->_serviceRecords[j-2])
            (void)this->_sendMDNSMessage(iUdp.remoteIP(), xid, (int)MDNSPacketTypeServiceRecord, j-2);
      }
   }
   
   // if we were asked for our IPv6 address, say that we don't have any
   if (wantsIPv6Addr)
      (void)this->_sendMDNSMessage(iUdp.remoteIP(), xid, (int)MDNSPacketTypeNoIPv6AddrAvailable, 0);
   
   return statusCode;
}

void EthernetBonjourClass::run()
{
   uint8_t i;
   unsigned long now = millis();
   
   // first, look for MDNS queries to handle
   (void)_processMDNSQuery();
   
   // are we querying a name or service? if so, should we resend the packet or time out?
   for (i=0; i<2; i++) {
      if (NULL != this->_resolveNames[i]) {
         // Hint: _resolveLastSendMillis is updated in _sendMDNSMessage
         if (now - this->_resolveLastSendMillis[i] > ((i == 0) ? (uint32_t)MDNS_NQUERY_RESEND_TIME :
                                                                 (uint32_t)MDNS_SQUERY_RESEND_TIME))
            (void)this->_sendMDNSMessage(0,
                                         0,
                                         (0 == i) ? MDNSPacketTypeNameQuery :
                                                    MDNSPacketTypeServiceQuery,
                                         0);
      
         if (this->_resolveTimeouts[i] > 0 && now > this->_resolveTimeouts[i]) {
            if (i == 0)
               this->_finishedResolvingName((char*)this->_resolveNames[0], NULL);
            else if (i == 1) {
               if (this->_serviceFoundCallback) {
                  char* typeName = (char*)this->_resolveNames[1];
                  char* p = (char*)this->_resolveNames[1];
                  while(*p && *p != '.')
                     p++;
                  *p = '\0';
               
                  this->_serviceFoundCallback(typeName,
                                              this->_resolveServiceProto,
                                              NULL,
                                              NULL,
                                              0,
                                              NULL);
               }
            }
               
            if (NULL != this->_resolveNames[i]) {
               my_free(this->_resolveNames[i]);
               this->_resolveNames[i] = NULL;
            }
         }
      }
   }
   
   // now, should we re-announce our services again?
   unsigned long announceTimeOut = (((uint32_t)MDNS_RESPONSE_TTL/2)+((uint32_t)MDNS_RESPONSE_TTL/4));
   if ((now - this->_lastAnnounceMillis) > 1000*announceTimeOut) {
      for (i=0; i<NumMDNSServiceRecords; i++) {
         if (NULL != this->_serviceRecords[i])
            (void)this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecord, i);
      }
      
      this->_lastAnnounceMillis = now;
   }
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::setBonjourName(const char* bonjourName)
{
   if (NULL == bonjourName)
      return 0;
         
   if (this->_bonjourName != NULL)
      my_free(this->_bonjourName);
   
   this->_bonjourName = (uint8_t*)my_malloc(strlen(bonjourName) + 7);
   if (NULL == this->_bonjourName)
      return 0;
   
   strcpy((char*)this->_bonjourName, bonjourName);
   strcpy((char*)this->_bonjourName+strlen(bonjourName), MDNS_TLD);
   
   return 1;
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::addServiceRecord(const char* name, uint16_t port,
                                           MDNSServiceProtocol_t proto)
{
   return this->addServiceRecord(name, port, proto, NULL);
}

// return values:
// 1 on success
// 0 otherwise
int EthernetBonjourClass::addServiceRecord(const char* name, uint16_t port,
                                           MDNSServiceProtocol_t proto, const char* textContent)
{
   int i, status = 0;
   MDNSServiceRecord_t* record = NULL;
      
   if (NULL != name && 0 != port) {
      for (i=0; i < NumMDNSServiceRecords; i++) {
         if (NULL == this->_serviceRecords[i]) {
            record = (MDNSServiceRecord_t*)my_malloc(sizeof(MDNSServiceRecord_t));
            if (NULL != record) {
               record->name = record->textContent = NULL;
               
               record->name = (uint8_t*)my_malloc(strlen((char*)name));
               if (NULL == record->name)
                  goto errorReturn;
               
               if (NULL != textContent) {
                  record->textContent = (uint8_t*)my_malloc(strlen((char*)textContent));
                  if (NULL == record->textContent)
                     goto errorReturn;
                  
                  strcpy((char*)record->textContent, textContent);
               }
               
               record->port = port;
               record->proto = proto;
               strcpy((char*)record->name, name);
               
               uint8_t* s = this->_findFirstDotFromRight(record->name);
               record->servName = (uint8_t*)my_malloc(strlen((char*)s) + 12);
               if (record->servName) {
                  strcpy((char*)record->servName, (const char*)s);

                  const uint8_t* srv_type = this->_postfixForProtocol(proto);
                  if (srv_type)
                     strcat((char*)record->servName, (const char*)srv_type);
               }

               this->_serviceRecords[i] = record;
                              
               status = (MDNSSuccess ==
                           this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecord, i));
               
               break;
            }
         }
      }
   }
   
   return status;

errorReturn:
   if (NULL != record) {
      if (NULL != record->name)
         my_free(record->name);
      if (NULL != record->servName)
         my_free(record->servName);
      if (NULL != record->textContent)
         my_free(record->textContent);
      
      my_free(record);
   }
   
   return 0;
}

void EthernetBonjourClass::_removeServiceRecord(int idx)
{
   if (NULL != this->_serviceRecords[idx]) {
      (void)this->_sendMDNSMessage(0, 0, (int)MDNSPacketTypeServiceRecordRelease, idx);
      
      if (NULL != this->_serviceRecords[idx]->textContent)
         my_free(this->_serviceRecords[idx]->textContent);
      
      if (NULL != this->_serviceRecords[idx]->servName)
         my_free(this->_serviceRecords[idx]->servName);
      
      my_free(this->_serviceRecords[idx]->name);
      my_free(this->_serviceRecords[idx]);
      
      this->_serviceRecords[idx] = NULL;
   }
}

void EthernetBonjourClass::removeServiceRecord(uint16_t port, MDNSServiceProtocol_t proto)
{
   this->removeServiceRecord(NULL, port, proto);
}

void EthernetBonjourClass::removeServiceRecord(const char* name, uint16_t port,
                                               MDNSServiceProtocol_t proto)
{
   int i;
   for (i=0; i<NumMDNSServiceRecords; i++)
      if (port == this->_serviceRecords[i]->port &&
          proto == this->_serviceRecords[i]->proto &&
          (NULL == name || 0 == strcmp((char*)this->_serviceRecords[i]->name, name))) {
             this->_removeServiceRecord(i);
             break;
          }
}

void EthernetBonjourClass::removeAllServiceRecords()
{
   int i;
   for (i=0; i<NumMDNSServiceRecords; i++)
      this->_removeServiceRecord(i);
}

void EthernetBonjourClass::_writeDNSName(const uint8_t* name, int zeroTerminate)
{
   uint8_t* p1 = (uint8_t*)name, *p2, *p3;
   int i, c, len;
   const int bufSize = 20;//TODO
   uint8_t buf[bufSize];
   
   while(*p1) {
      c = 1;
      p2 = p1;
      while (0 != *p2 && '.' != *p2) { p2++; c++; };

      p3 = buf;
      i = c;
      len = bufSize-1;
      *p3++ = (uint8_t)--i;
      while (i-- > 0) {
         *p3++ = *p1++;

         if (--len <= 0) {
            iUdp.write((uint8_t*)buf,bufSize);
            len = bufSize;
            p3 = buf;
         }
      }

      while ('.' == *p1)
         ++p1;

      if (len != bufSize) {
         iUdp.write((uint8_t*)buf,bufSize-len);
      }
   }
   
   if (zeroTerminate) {
      buf[0] = 0;
      iUdp.write((uint8_t*)buf,1);
   }
}

void EthernetBonjourClass::_writeMyIPAnswerRecord()
{
   this->_writeDNSName(this->_bonjourName, 1);

   uint8_t buf[10];
   buf[0] = 0x00;
   buf[1] = 0x01;
   buf[2] = 0x80; // cache flush: true
   buf[3] = 0x01;
   iUdp.write((uint8_t*)buf,4);

   *((uint32_t*)buf) = htonl_(MDNS_RESPONSE_TTL);
   *((uint16_t*)&buf[4]) = htons_(4);      // data length

   uint8_t myIp[4];
   W5100.readSIPR(myIp);
   memcpy(&buf[6], myIp, 4);              // our IP address

   iUdp.write((uint8_t*)buf,10);
}

void EthernetBonjourClass::_writeServiceRecordName(int recordIndex, int tld)
{
   uint8_t* name = tld ? this->_serviceRecords[recordIndex]->servName :
                         this->_serviceRecords[recordIndex]->name;
   
   this->_writeDNSName(name, tld);
   
   if (0 == tld) {
      const uint8_t* srv_type =
         this->_postfixForProtocol(this->_serviceRecords[recordIndex]->proto);
   
      if (NULL != srv_type) {
         srv_type++; // eat the dot at the beginning
         this->_writeDNSName(srv_type, 1);
      }
   }
}

void EthernetBonjourClass::_writeServiceRecordPTR(int recordIndex, uint32_t ttl)
{
   this->_writeServiceRecordName(recordIndex, 1);
   
   uint8_t buf[10];
   buf[0] = 0x00;
   buf[1] = 0x0c;    // PTR record
   buf[2] = 0x00;    // no cache flush
   buf[3] = 0x01;    // class IN
   
   // ttl
   *((uint32_t*)&buf[4]) = htonl_(ttl);
   
   // data length (+13 = "._tcp.local" or "._udp.local" + 1  byte zero termination)
   *((uint16_t*)&buf[8]) =
         htons_(strlen((char*)this->_serviceRecords[recordIndex]->name) + 13);
   
   iUdp.write((uint8_t*)buf,10);
   
   this->_writeServiceRecordName(recordIndex, 0);
}

uint8_t* EthernetBonjourClass::_findFirstDotFromRight(const uint8_t* str)
{
   const uint8_t* p = str + strlen((char*)str);
   while (p > str && '.' != *p--);
   return (uint8_t*)&p[2];
}

int EthernetBonjourClass::_matchStringPart(const uint8_t** pCmpStr, int* pCmpLen, const uint8_t* buf,
                                           int dataLen)
{
   int matches = 1;

   if (*pCmpLen >= dataLen)
      matches &= (0 == memcmp(*pCmpStr, buf, dataLen));
   else
      matches = 0;

   *pCmpStr += dataLen;
   *pCmpLen -= dataLen;
   if ('.' == **pCmpStr)
      (*pCmpStr)++, (*pCmpLen)--;

   return matches;
}

const uint8_t* EthernetBonjourClass::_postfixForProtocol(MDNSServiceProtocol_t proto)
{
   const uint8_t* srv_type = NULL;
   switch(proto) {
      case MDNSServiceTCP:
         srv_type = (uint8_t*)"._tcp" MDNS_TLD;
         break;
      case MDNSServiceUDP:
         srv_type = (uint8_t*)"._udp" MDNS_TLD;
         break;
   }
   
   return srv_type;
}

void EthernetBonjourClass::_finishedResolvingName(char* name, const byte ipAddr[4])
{   
   if (NULL != this->_nameFoundCallback) {
      if (NULL != name) {
         uint8_t* n = this->_findFirstDotFromRight((const uint8_t*)name);
         *(n-1) = '\0';
      }
   
      this->_nameFoundCallback((const char*)name, ipAddr);
   }

   my_free(this->_resolveNames[0]);
   this->_resolveNames[0] = NULL;
}

EthernetBonjourClass EthernetBonjour;
