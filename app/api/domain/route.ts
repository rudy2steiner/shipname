import { NextResponse } from 'next/server';
import whois from 'whois-parsed-v2';

interface WhoisResponse {
  status: 'available' | 'unavailable' | 'error';
  tld: string; // Add tld to the interface
  registrar?: string;
  createdDate?: string;
  expiresDate?: string;
  error?: string;
  whoisData?: {
    nameServers?: string[];
    rawText?: string;
    registrant?: any;
    admin?: any;
    tech?: any;
  };
}

async function queryDomain(domain: string, tld: string): Promise<WhoisResponse> {
  try {
    console.log('query:'+domain);
    const result = domain.includes('com')?{
      "domainName": "imagemaker.com",
      "registrar": "Name.com, Inc.",
      "updatedDate": "2019-10-22T17:57:15.000Z",
      "creationDate": "1995-10-29T04:00:00.000Z",
      "expirationDate": "2028-10-28T04:00:00.000Z",
      "status": [
          "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
      ],
      "nameServers": [
          "NS12.WIXDNS.NET",
          "NS13.WIXDNS.NET"
      ],
      "isAvailable": false,
      "raw": "   Domain Name: IMAGEMAKER.COM\r\n   Registry Domain ID: 2947_DOMAIN_COM-VRSN\r\n   Registrar WHOIS Server: whois.name.com\r\n   Registrar URL: http://www.name.com\r\n   Updated Date: 2019-10-22T17:57:15Z\r\n   Creation Date: 1995-10-29T04:00:00Z\r\n   Registry Expiry Date: 2028-10-28T04:00:00Z\r\n   Registrar: Name.com, Inc.\r\n   Registrar IANA ID: 625\r\n   Registrar Abuse Contact Email: abuse@name.com\r\n   Registrar Abuse Contact Phone: 7202492374\r\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\r\n   Name Server: NS12.WIXDNS.NET\r\n   Name Server: NS13.WIXDNS.NET\r\n   DNSSEC: unsigned\r\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\r\n>>> Last update of whois database: 2025-02-03T03:56:49Z <<<\r\n\r\nFor more information on Whois status codes, please visit https://icann.org/epp\r\n\r\nNOTICE: The expiration date displayed in this record is the date the\r\nregistrar's sponsorship of the domain name registration in the registry is\r\ncurrently set to expire. This date does not necessarily reflect the expiration\r\ndate of the domain name registrant's agreement with the sponsoring\r\nregistrar.  Users may consult the sponsoring registrar's Whois database to\r\nview the registrar's reported date of expiration for this registration.\r\n\r\nTERMS OF USE: You are not authorized to access or query our Whois\r\ndatabase through the use of electronic processes that are high-volume and\r\nautomated except as reasonably necessary to register domain names or\r\nmodify existing registrations; the Data in VeriSign Global Registry\r\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\r\ninformation purposes only, and to assist persons in obtaining information\r\nabout or related to a domain name registration record. VeriSign does not\r\nguarantee its accuracy. By submitting a Whois query, you agree to abide\r\nby the following terms of use: You agree that you may use this Data only\r\nfor lawful purposes and that under no circumstances will you use this Data\r\nto: (1) allow, enable, or otherwise support the transmission of mass\r\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\r\nor facsimile; or (2) enable high volume, automated, electronic processes\r\nthat apply to VeriSign (or its computer systems). The compilation,\r\nrepackaging, dissemination or other use of this Data is expressly\r\nprohibited without the prior written consent of VeriSign. You agree not to\r\nuse electronic processes that are automated and high-volume to access or\r\nquery the Whois database except as reasonably necessary to register\r\ndomain names or modify existing registrations. VeriSign reserves the right\r\nto restrict your access to the Whois database in its sole discretion to ensure\r\noperational stability.  VeriSign may restrict or terminate your access to the\r\nWhois database for failure to abide by these terms of use. VeriSign\r\nreserves the right to modify these terms at any time.\r\n\r\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\r\nRegistrars.\r\n"
    }:{
      "domainName": "imagemaker2000.com",
      "isAvailable": true,
      "raw": "No match for domain \"IMAGEMAKER2000.COM\".\r\n>>> Last update of whois database: 2025-02-03T04:49:55Z <<<\r\n\r\nNOTICE: The expiration date displayed in this record is the date the\r\nregistrar's sponsorship of the domain name registration in the registry is\r\ncurrently set to expire. This date does not necessarily reflect the expiration\r\ndate of the domain name registrant's agreement with the sponsoring\r\nregistrar.  Users may consult the sponsoring registrar's Whois database to\r\nview the registrar's reported date of expiration for this registration.\r\n\r\nTERMS OF USE: You are not authorized to access or query our Whois\r\ndatabase through the use of electronic processes that are high-volume and\r\nautomated except as reasonably necessary to register domain names or\r\nmodify existing registrations; the Data in VeriSign Global Registry\r\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\r\ninformation purposes only, and to assist persons in obtaining information\r\nabout or related to a domain name registration record. VeriSign does not\r\nguarantee its accuracy. By submitting a Whois query, you agree to abide\r\nby the following terms of use: You agree that you may use this Data only\r\nfor lawful purposes and that under no circumstances will you use this Data\r\nto: (1) allow, enable, or otherwise support the transmission of mass\r\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\r\nor facsimile; or (2) enable high volume, automated, electronic processes\r\nthat apply to VeriSign (or its computer systems). The compilation,\r\nrepackaging, dissemination or other use of this Data is expressly\r\nprohibited without the prior written consent of VeriSign. You agree not to\r\nuse electronic processes that are automated and high-volume to access or\r\nquery the Whois database except as reasonably necessary to register\r\ndomain names or modify existing registrations. VeriSign reserves the right\r\nto restrict your access to the Whois database in its sole discretion to ensure\r\noperational stability.  VeriSign may restrict or terminate your access to the\r\nWhois database for failure to abide by these terms of use. VeriSign\r\nreserves the right to modify these terms at any time.\r\n\r\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\r\nRegistrars.\r\n"
    };

    console.log('query:'+domain+',result:\n'+JSON.stringify(result));

    // Check if domain is available based on isAvailable flag
    if (result.isAvailable) {
      return {
        status: 'available',
        tld,
        whoisData: {
          rawText: result.raw
        }
      };
    }
    
    // Domain is registered
    return {
      status: 'unavailable',
      tld,
      registrar: result.registrar || 'Unknown',
      createdDate: result.creationDate,
      expiresDate: result.expirationDate,
      whoisData: {
        nameServers: result.nameServers || [],
        rawText: result.raw,
        registrant: result.registrant,
        admin: result.admin,
        tech: result.tech
      }
    };
  } catch (error) {
    // Check if the error indicates the domain is available
    if (error.message?.includes('No match for domain') || 
        error.message?.includes('Domain not found') ||
        error.message?.includes('Status: AVAILABLE')) {
      return {
        status: 'available',
        tld,
        whoisData: { rawText: error.message }
      };
    }

    console.error('Domain lookup error:', error);
    return {
      status: 'error',
      tld,
      error: error.message || 'Failed to check domain availability'
    };
  }
}

export async function POST(request: Request) {
  try {
    const { domain, tld } = await request.json();
    
    if (!domain || !tld) {
      return NextResponse.json(
        { error: 'Domain and TLD are required' },
        { status: 400 }
      );
    }

    // Validate domain name format
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$/;
    if (!domainRegex.test(domain)) {
      return NextResponse.json(
        { error: 'Invalid domain name format' },
        { status: 400 }
      );
    }

    const result = await queryDomain(`${domain}.${tld}`, tld);
    return NextResponse.json(result);

  } catch (error) {
    console.error('Domain check error:', error);
    return NextResponse.json(
      { 
        status: 'error',
        error: 'Failed to check domain availability',
        details: error.message
      },
      { status: 500 }
    );
  }
}