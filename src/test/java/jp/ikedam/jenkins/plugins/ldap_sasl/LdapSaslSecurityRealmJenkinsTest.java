/*
 * The MIT License
 * 
 * Copyright (c) 2012-2013 IKEDA Yasuyuki
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package jp.ikedam.jenkins.plugins.ldap_sasl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;

import jenkins.model.Jenkins;

import hudson.XmlFile;
import hudson.model.AutoCompletionCandidates;
import hudson.util.FormValidation;

import org.apache.commons.lang.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.xml.sax.SAXException;

import static org.junit.Assert.*;

/**
 * Tests for LdapSaslSecurityRealm concerned with Jenkins.
 */
public class LdapSaslSecurityRealmJenkinsTest
{
    @Rule
    public JenkinsRule j = new JenkinsRule();
    
    private LdapSaslSecurityRealm.DescriptorImpl getDescriptor()
    {
        return new LdapSaslSecurityRealm.DescriptorImpl();
        //return (LdapSaslSecurityRealm.DescriptorImpl)new LdapSaslSecurityRealm(null, null, null, null, 0, 0).getDescriptor();
    }
    
    @Test
    public void testDescriptorGetMechanismCandidates()
    {
        LdapSaslSecurityRealm.DescriptorImpl descriptor = getDescriptor();
        assertFalse("Returns valid candidates", 0 == descriptor.getMechanismCandidates().length);
    }
    
    @Test
    public void testDescriptorDoAutoCompleteMechanisms()
    {
        LdapSaslSecurityRealm.DescriptorImpl descriptor = getDescriptor();
        
        // empty
        {
            AutoCompletionCandidates candidates = descriptor.doAutoCompleteMechanisms("", "");
            assertTrue("Return candidates for null inputs", 0 < candidates.getValues().size());
        }
        
        // partial
        {
            AutoCompletionCandidates candidates = descriptor.doAutoCompleteMechanisms("DIGEST-MD", "");
            assertEquals("Return the candidate for partial input", 1, candidates.getValues().size());
        }
        
        // complete
        {
            AutoCompletionCandidates candidates = descriptor.doAutoCompleteMechanisms("DIGEST-MD5", "");
            assertEquals("Return the candidate for complete input", 1, candidates.getValues().size());
        }
        
        // none for overrun
        {
            AutoCompletionCandidates candidates = descriptor.doAutoCompleteMechanisms("DIGEST-MD5X", "");
            assertEquals("Return no candidate for overrun input", 0, candidates.getValues().size());
        }
        
        // Don't return used value
        {
            AutoCompletionCandidates beforeCandidates = descriptor.doAutoCompleteMechanisms("", "");
            AutoCompletionCandidates afterCandidates = descriptor.doAutoCompleteMechanisms("", "DIGEST-MD5");
            assertEquals("Don't return used value", beforeCandidates.getValues().size(), afterCandidates.getValues().size() + 1);
        }
        
        // Don't return used value, 2 values separated with a space
        {
            AutoCompletionCandidates beforeCandidates = descriptor.doAutoCompleteMechanisms("", "");
            AutoCompletionCandidates afterCandidates = descriptor.doAutoCompleteMechanisms("", "DIGEST-MD5 CRAM-MD5");
            assertEquals("Don't return used value, 2 values separated with a space", beforeCandidates.getValues().size(), afterCandidates.getValues().size() + 2);
        }
        
        // Don't return used value, 2 values separated with a comma
        {
            AutoCompletionCandidates beforeCandidates = descriptor.doAutoCompleteMechanisms("", "");
            AutoCompletionCandidates afterCandidates = descriptor.doAutoCompleteMechanisms("", "DIGEST-MD5,CRAM-MD5");
            assertEquals("Don't return used value, 2 values separated with a comma", beforeCandidates.getValues().size(), afterCandidates.getValues().size() + 2);
        }
        
        // Works with null inputs.
        {
            AutoCompletionCandidates candidates = descriptor.doAutoCompleteMechanisms(null, null);
            assertTrue("Works with null inputs", 0 < candidates.getValues().size());
        }
    }
    
    @Test
    public void testDescriptorDoCheckLdapUriList_Success()
    {
        LdapSaslSecurityRealm.DescriptorImpl descriptor = getDescriptor();
        
        // ldap smallest uri
        {
            assertEquals("ldap smallest uri",
                    FormValidation.Kind.OK,
                    descriptor.doCheckLdapUriList("ldap:///").kind);
        }
        
        // ldap largest uri
        {
            assertEquals("ldap largest uri",
                    FormValidation.Kind.OK,
                    descriptor.doCheckLdapUriList("LDaP://somehost:8389/dc=example,dc=com").kind);
        }
        
        // ldaps smallest uri
        {
            assertEquals("ldaps smallest uri",
                    FormValidation.Kind.WARNING,
                    descriptor.doCheckLdapUriList("ldaps:///").kind);
        }
        
        // ldaps largest uri
        {
            assertEquals(
                    "ldaps largest uri",
                    FormValidation.Kind.WARNING,
                    descriptor.doCheckLdapUriList("lDAPs://somehost:8636/dc=example,dc=com").kind);
        }
        
    }
    @Test
    public void testDescriptorDoCheckLdapUriList_Failure()
    {
        LdapSaslSecurityRealm.DescriptorImpl descriptor = getDescriptor();
        
        // null
        {
            assertEquals("null",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList(null).kind
                    );
        }
        
        // empty
        {
            assertEquals("empty",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("").kind);
        }
        
        // blank
        {
            assertEquals("blank",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList(" ").kind);
        }
        
        // non-url
        {
            assertEquals("non-url",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("hogehoge").kind);
        }
        
        // empty schema
        {
            assertEquals(
                    "empty schema",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("://localhost/").kind);
        }
        
        // bad schema
        {
            assertEquals(
                    "bad schema",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("http://localhost/").kind);
        }
        
        // invalid port
        {
            // invalid port is ignored.
            assertEquals(
                    "invalid port",
                    FormValidation.Kind.OK,
                    descriptor.doCheckLdapUriList("ldap://localhost:aaa/").kind);
        }
        
        // port < 0
        {
            // invalid port is ignored.
            assertEquals(
                    "port < 0",
                    FormValidation.Kind.OK,
                    descriptor.doCheckLdapUriList("ldap://localhost:-2/").kind);
        }
        
        // port == 0
        {
            assertEquals(
                    "port == 0",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("ldap://localhost:0/").kind);
        }
        
        // port == 1
        {
            assertEquals(
                    "port == 1",
                    FormValidation.Kind.OK,
                    descriptor.doCheckLdapUriList("ldap://localhost:1/").kind);
        }
        
        // port == 65535
        {
            assertEquals(
                    "port == 65535",
                    FormValidation.Kind.OK,
                    descriptor.doCheckLdapUriList("ldap://:65535/").kind);
        }
        
        // port > 65535
        {
            assertEquals(
                    "port > 65535",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("ldap://localhost:65536/").kind);
        }
        
        // have user info
        {
            assertEquals(
                    "have user info",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("ldap://user@localhost/").kind);
        }
        
        // have user and password info
        {
            assertEquals(
                    "have user and password info",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("ldap://user:password@localhost/").kind);
        }
        
        // have query
        {
            assertEquals(
                    "have query",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("ldap://localhost/?query").kind);
        }
        
        // have fragment
        {
            assertEquals(
                    "have fragment",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("ldap://localhost/#fragment").kind);
        }
        
        // bad DN
        {
            assertEquals(
                    "bad DN",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckLdapUriList("ldap://localhost/hogehoge").kind);
        }
    }
    
    @Test
    public void testDoCheckMechanisms_Success()
    {
        LdapSaslSecurityRealm.DescriptorImpl descriptor = getDescriptor();
        // one value
        {
            assertEquals(
                    "one value",
                    FormValidation.Kind.OK,
                    descriptor.doCheckMechanisms("DIGEST-MD5").kind
                    );
        }
        
        // two value separated with a space
        {
            assertEquals(
                    "two value separated with a space",
                    FormValidation.Kind.OK,
                    descriptor.doCheckMechanisms("DIGEST-MD5 CRAM-MD5").kind
                    );
        }
        
        // two value separated with comma
        {
            assertEquals(
                    "two value separated with comma",
                    FormValidation.Kind.OK,
                    descriptor.doCheckMechanisms("DIGEST-MD5,CRAM-MD5").kind
                    );
        }
    }
    
    
    @Test
    public void testDoCheckMechanisms_Failure()
    {
        LdapSaslSecurityRealm.DescriptorImpl descriptor = getDescriptor();
        // null
        {
            assertEquals(
                    "null",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckMechanisms(null).kind
                    );
        }
        
        // empty
        {
            assertEquals(
                    "empty",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckMechanisms("").kind
                    );
        }
        
        // blank
        {
            assertEquals(
                    "blank",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckMechanisms("  ").kind
                    );
        }
        
        // only separator
        {
            assertEquals(
                    "only separator",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckMechanisms(" , ,").kind
                    );
        }
    }
    
    @Test
    public void testGetValidLdapUris()
    {
        // filters bad uris
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            "",
                            "ldap:///",
                            null,
                            "http:///",
                            "ldaps:///"
                    ),
                    null,
                    null,
                    null,
                    0,
                    0
                    );
            assertEquals("filters bad uris", "ldap:/// ldaps:///", target.getValidLdapUris());
        }
        
        // when all are filtered
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            new String(""),
                            new String("http:///")
                    ),
                    null,
                    null,
                    null,
                    0,
                    0
                    );
            assertNull("when all are filtered", target.getValidLdapUris());
        }
        
        // work with null
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    null,
                    null,
                    null,
                    null,
                    0,
                    0
                    );
            assertNull("work with null", target.getValidLdapUris());
        }
    }
    
    @Test
    public void testView() throws IOException, SAXException
    {
        // Test no HTML exception occurs
        {
            WebClient wc = j.createWebClient();
            wc.goTo("configure");
        }
    }
    
    private File getResource(String name) throws URISyntaxException, FileNotFoundException
    {
        String filename = String.format("%s/%s", StringUtils.join(getClass().getName().split("\\."), "/"), name);
        URL url = ClassLoader.getSystemResource(filename);
        if(url == null)
        {
            throw new FileNotFoundException(String.format("Not found: %s", filename));
        }
        return new File(url.toURI());
    }
    
    @Test
    public void testReadResolve() throws URISyntaxException, IOException
    {
        // compatibility with 0.1.0: no configuration for group.
        {
            XmlFile xmlFile = new XmlFile(
                    Jenkins.XSTREAM,
                    getResource("config-0.1.0_01.xml")
                    );
            LdapSaslSecurityRealm target = (LdapSaslSecurityRealm)xmlFile.read();
            assertEquals("compatibility with 0.1.0: no configuration for group.",
                    LdapWhoamiUserDnResolver.class,
                    target.getUserDnResolver().getClass()
                    );
            assertEquals("compatibility with 0.1.0: no configuration for group.",
                    NoGroupResolver.class,
                    target.getGroupResolver().getClass()
                    );
        }
        
        // compatibility with 0.1.0: configured for group.
        {
            XmlFile xmlFile = new XmlFile(
                    Jenkins.XSTREAM,
                    getResource("config-0.1.0_02.xml")
                    );
            LdapSaslSecurityRealm target = (LdapSaslSecurityRealm)xmlFile.read();
            assertEquals("compatibility with 0.1.0: configured for group.",
                    LdapWhoamiUserDnResolver.class,
                    target.getUserDnResolver().getClass()
                    );
            assertEquals("compatibility with 0.1.0: configured for group.",
                    SearchGroupResolver.class,
                    target.getGroupResolver().getClass()
                    );
            SearchGroupResolver searchGroupResolver = (SearchGroupResolver)target.getGroupResolver();
            assertEquals("compatibility with 0.1.0: configured for group.",
                    "dc=example,dc=com",
                    searchGroupResolver.getSearchBase()
                    );
            assertEquals("compatibility with 0.1.0: configured for group.",
                    "ROLE_",
                    searchGroupResolver.getPrefix()
                    );
        }
    }
}
