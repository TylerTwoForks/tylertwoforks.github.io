---
layout: post
title:  "My First Post"
date:   2025-03-09 14:34:12 -0500
categories: jekyll update
tags: blarg java
---

# Consume 3rd Party SOAP API in Salesforce with Apex and WS Security Header
![alt text](/_site/assets/testImage.webp)
<img src="{{site.baseurl}}/assets/testImage.webp">

NOTE: this is not a full guide on integrating a SOAP API. This starts after I've already converted WSDL2Soap and have the generated Apex classes in place. I have also already configured the Remote Site Settings to accept the URL for the SOAP requests. Please comment if you would like a more in depth walkthrough from the very beginning.

---

Tools used in this article
IntelliJ with Illuminated Cloud 2 (but you can do it all in VSCode as well)
Postman
Beeceptor free online mock server utility for intercepting callouts to review the xml. (I am not affiliated in any way and this is not an affiliate link. It was just an easy tool to use.)

---

I was tasked with integrating a 3rd party service that I had never used before and my first thought was "awesome, this will be pretty easy to integrate with a REST API". Well, lo-and-behold, the API was built with SOAP! So starts my journey.
The 3rd party has provided their WSDL files and I have my generated Apex classes from Wsdl2Apex. We now have the ability to easily hit the SOAP endpoints.
But before we can see success, we have to work through the security issues. This is to be expected at this point since I had a Username and Password to connect to the SOAP API and I hadn't implemented them anywhere yet.
I was hit with the following error when trying to hit one of the simple GET methods.
WebService returned a SOAP Fault: An error occurred when verifying security for the message. faultcode=a:InvalidSecurity

---

Now I'm off to find out how to implement the security header. I needed to test the endpoint in Postman at this point because I knew I could add the authentication there. The following Soap Envelope is the result of a successful call to my live endpoint (with some censored information).
<soapenv:Envelope xmlns:dsi="dsiurl" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Header>
  <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
   <wsse:UsernameToken wsu:Id="UsernameToken-123">
    <wsse:Username>ThisIsMyUsername</wsse:Username>
    <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">thisismypassword</wsse:Password>
    <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">thisismynonce</wsse:Nonce>
    <wsu:Created>2099-12-05T17:26:08.843Z</wsu:Created>
   </wsse:UsernameToken>
  </wsse:Security>
 </soapenv:Header>
 <soapenv:Body>
  <MyEndpoint xmlns="https://www.thisismySOAPdomain.com/dsi"/>
 </soapenv:Body>
</soapenv:Envelope>
As you can see, there is a <wsse:security> tag with some other information inside of it.
We have a successful example at this point and now just need to see the XML of the callout from Apex. No XML was being posted to my Dev Console for review, at least with any of the logging settings I configured so I had to figure out how to see this XML envelope. This is when I found ttps://beeceptor.com/. This Mock Server is like a mischievous imposter, mimicking a real server to help you test and simulate HTTP responses without relying on the actual service you're calling.

---

NOTE: You just need to go to the Beeceptor website > type in a test endpoint name > create > copy the URL that's generated > and update your WSDL endpoint code to point to this new URL. Then update the Remote Site Settings in the sandbox you're working on with the new URL of the test endpoint.

---

Once we hit the Beeceptor endpoint, we can see the following results:
<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <env:Header />
 <env:Body>
  <MyEndpoint xmlns="https://www.MYSOAPAPI.com/dsi" />
 </env:Body>
</env:Envelope>
At this point, you can tell we're missing quite a bit compared to the successful <Envelope> we got from Postman. Let's break down the differences.
NOTE: the words prior to the colon (:) in the xml tags are namespace prefixes and XML will parse those out. So it does not matter that the Postman success XML and the actual callout XML have different namespace prefix. <env:Envelope> vs <soapenv:Envelope>
<Security> is the first missing tag you can see.
<UsernameToken> is the second which is under <Security>
Then we have <Username>, <Password>, <Nonce>, and <Created> tags missing under <UsernameToken>

Security
    UsernameToken 
        Username
        Password
        Nonce
        Created
NOTE: Nonce and Created: a Nonce is a single use randomly generated key used in cryptographic communication. Although using a nonce is an effective countermeasure against replay attacks, it requires a server to maintain a cache of used nonces, consuming server resources. Combining a nonce with a creation timestamp (Created) has the advantage of allowing a server to limit the cache of nonces to a "freshness" time period, establishing an upper bound on resource requirements.
I found that WSDL2Apex does not support the Security Headers out of the box and you have to write some of your own code in order to get this working. Luckily for us, the structure of the above XML will fit into an Apex class quite nicely.

---

Let's get into the code now. First, we need to create a security class to wrap our information in. I am not a SOAP wizard by any means. I used a sprinkling of Stack Overflow articles and guess work based on the structure of the generated Apex classes from WSDL2Apex to create this solution.
Below is the Security class that I created. This is the base class we're going to use to generate our Security Header to inject in the SOAP callout. We have a subclass named UsernameToken that will represent the token tag and contain most of the goodies.
public class Security {

    private final static String wsuNamespace = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private final String[] UsernameToken_type_info = new String[]{'UsernameToken','http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd','UsernameToken','1','1','false'};
    private final String[] wsuNamespace_att_info = new String[]{'xmlns:wsu'};
    private final String[] apex_schema_type_info = new String[]{'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd','true','false'};
    private final String[] field_order_type_info = new String[]{'UsernameToken'};

    private final Security.UsernameToken UsernameToken;

    public Security(String username, String password){
        this.UsernameToken = new Security.UsernameToken(username, password);
    }

    /**
     * Inner Class
     * <UsernameToken> representation
     */
    private class UsernameToken {

        private final String Username;
        private final String Password;
        private final String Nonce;
        private final String Created;
        private final String[] Username_type_info = new String[]{'Username','http://www.w3.org/2001/XMLSchema','string','0','1','false'};
        private final String[] Password_type_info = new String[]{'Password','http://www.w3.org/2001/XMLSchema','string','0','1','false'};
        private final String[] Nonce_type_info = new String[]{'Nonce','http://www.w3.org/2001/XMLSchema','string','0','1','false'};
        private final String[] Created_type_info = new String[]{'wsu:Created','http://www.w3.org/2001/XMLSchema','string','0','1','false'};
        private final String[] apex_schema_type_info = new String[]{'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd','true','false'};
        private final String[] field_order_type_info = new String[]{'Username','Password','Nonce','Created'};

        // Constructor for UsernameToken used to pass in username and password parameters
        private UsernameToken(String username, String password){
            this.Username = username;
            this.Password = password;
            this.Nonce = generateNonce();
            this.Created = String.valueOf(Datetime.now());
        }

        // Generate Nonce as base64 encoded.
        // a nonce is an arbitrary number that can be used once in cryptographic communication.
        private String generateNonce(){
            Long randomLong = Crypto.getRandomLong();
            return EncodingUtil.base64Encode(Blob.valueOf(String.valueOf(randomLong)));
        }

    }
}
Let's break down the class.
First, the main class represents the first missing tag <Security> and it contains an instance of the UsernameToken class.
The constructor here let's us instantiate an instance of the UsernameToken class and set Username/Password.
If we look at the UsernameToken class, we can see that it has the remaining fields we're looking for.
Because Nonce needs to be a randomly base 64 encoded key, I created a helper method to generate said Nonce.

If you noticed, the only public keywords are for the class and the constructor of the class. Every other field is private, final, and only able to be set in the constructors of their classes. This helps with preventing the Security class from being modified once it's generated.
Also, all of the String arrays (String[]) are SOAP requirements. I created these by looking at the generated class from WSDL2Apex and piecing them together. It was pretty straight forward.
Now to get into the WSDL2Apex genreated class and how to implement this security header.
This is a lot of boilerplate code that was fully generated by WSDL2Apex. If you have gone through that process, you should have a similar class.
The Javadoc comment in the middle of the page is our custom code and where the money happens.
To implement security, you just need to instantiate an instance of the class and pass in your credentials however you chose to handle that.
The next like with the Security_hns variable is where some salesforce magic happens. Soap headers can be inserted by creating a String variable with the following naming convention: "security variable name+_hns". This variable specifies the namespace for that object. In our case, we are using the wsse namespace from the Oasis Open Standard.
public with sharing class Wsdl2ApexGeneratedClass {
    private static final String s_ns0 = 'https://www.SOAPURL.com/dsi';

    public class BasicHttpBinding_MyEndpointMethods {
        //set this endpoint_x variable to hit Beeceptor
        public String endpoint_x = 'https://pentest.free.beeceptor.com';

        public Map<String, String> inputHttpHeaders_x;
        public Map<String, String> outputHttpHeaders_x;
        public String clientCertName_x;
        public String clientCert_x;
        public String clientCertPasswd_x;
        public Integer timeout_x;
        private transient String[] ns_map_type_info = new String[]{
                'https://www.SOAPURL.com/dsi', 'generatedValueFromWsdl2Apex',
                'http://schemas.microsoft.com/2003/10/Serialization/',
                'schemasMicrosoftCom200310Serializat',
                'http://schemas.datacontract.org/2004/07/PEN.Service.V4.ServiceTypes',
                'schemasDatacontractOrg200407PenServ',
                'http://schemas.datacontract.org/2004/07/Components.PENSystem.Enumerations',
                'schemasDatacontractOrg200407Compone',
                'http://schemas.microsoft.com/2003/10/Serialization/Arrays',
                'schemasMicrosoftCom200310Serializat1' };

        /**
         * this is the implementation of our Security class.
         */
        private final Security Security = new Security('FooName1', 'BarPassword2');
        private final String Security_hns = 'Security=http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

        public MySoapresponse GetFooMethod() {
            Request_element request_x = new Request_element();
            Response_element response_x;
            Map<String, Response_element> response_map_x = new Map<String, Response_element>();
            response_map_x.put('response_x', response_x);
            WebServiceCallout.invoke(
                    this, // stub - An instance of the Apex class that is auto-generated from a WSDL (the stub class).
                    request_x, // request - The request to the external service. The request is an instance of a type that is created as part of the auto-generated stub class.
                    response_map_x, // response
                    new String[]{endpoint_x, //  the URL of the external web service
                            'https://www.SOAPURL.com/dsi/route/GetFoo', // The SOAP action.
                            s_ns0, // The request namespace.
                            'GetFoo', // The request name.
                            s_ns0, // The response namespace.
                            'GetFooResponse', //  The response name.
                            'Response_element'} // The response type.
            );
            response_x = response_map_x.get('response_x');
            return response_x.GetResult;
        }

    }

}
NOTE: endpoint_x is the variable you would update to point to the Beeceptor mock server. Make sure to update this to point to your actual endpoint URL for actual testing once Security is implemented.

---

Now that we have our security in place, it's time to test our callout with Beeceptor! We can see the fruits of our labors here.
<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope
 xmlns:env="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <env:Header>
      <Security
       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
       xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
         <UsernameToken>
          <Username>FooName1</Username>
          <Password>BarPassword2</Password>
          <Nonce>LTQyNDM1MDMwNjIwNzM1MjUwNjQ=</Nonce>
          <wsu:Created>2024-02-05 03:47:47</wsu:Created>
         </UsernameToken>
      </Security>
   </env:Header>
 <env:Body>
  <GetProviders xmlns="https://www.SOAPURL.com/dsi" />
 </env:Body>
</env:Envelope>
And we can see success! I grabbed the above XML from Beeceptor after running my method in anonymous apex with the following code. This matches my example code above, so you would need to update it for your own method names and response types.
Wsdl2ApexGeneratedClass.BasicHttpBinding_MyEndpointMethods endpoint = new Wsdl2ApexGeneratedClass.BasicHttpBinding_MyEndpointMethods();
MySoapResponse response = endpoint.GetFooMethod();
Please let me know if you have any comments or questions! Best of luck.