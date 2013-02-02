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

import hudson.model.Descriptor;
import hudson.security.SecurityRealm;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.jvnet.hudson.test.For;
import org.opends.server.types.DirectoryEnvironmentConfig;
import org.opends.server.util.EmbeddedUtils;

import static org.junit.Assert.*;

/**
 * Test using LDAP.
 */
public class LdapTest
{
    private class MockLdapSaslSecurityRealm extends LdapSaslSecurityRealm
    {
        private static final long serialVersionUID = 7570611809102088684L;
        
        public MockLdapSaslSecurityRealm(List<String> ldapUriList,
                String mechanisms, UserDnResolver userDnResolver,
                GroupResolver groupResolver, int connectionTimeout,
                int readTimeout)
        {
            super(ldapUriList, mechanisms, userDnResolver, groupResolver,
                    connectionTimeout, readTimeout);
        }
        
        // For jenkins is not running,
        // default getDescriptor() fails...
        @Override
        public Descriptor<SecurityRealm> getDescriptor()
        {
            return new LdapSaslSecurityRealm.DescriptorImpl();
        }
    }
    
    static private int ldapPort = 8389;
    
    @BeforeClass
    public static void setupLdap() throws Exception
    {
        startLdapServer("config.ldif");
    }
    
    protected static void startLdapServer(String configFile) throws Exception
    {
        boolean isRunning = EmbeddedUtils.isRunning();
        if(isRunning)
        {
            EmbeddedUtils.stopServer(null, null);
        }
        File serverRoot = new File(ClassLoader.getSystemResource("opendj").toURI());
        DirectoryEnvironmentConfig config = new DirectoryEnvironmentConfig();
        config.disableAdminDataSynchronization();
        config.disableSynchronization();
        config.setUseLastKnownGoodConfiguration(false);
        config.setServerRoot(serverRoot);
        config.setConfigFile(new File(serverRoot, String.format("config/%s", configFile)));
        config.setSchemaDirectory(new File(serverRoot, "schema"));
        
        if(!isRunning)
        {
            File lockDir = new File(serverRoot, "locks");
            if(lockDir.exists())
            {
                FileUtils.deleteDirectory(lockDir);
            }
            lockDir.mkdir();
            config.setLockDirectory(lockDir);
            
            File logDir = new File(serverRoot, "logs");
            if(logDir.exists())
            {
                FileUtils.deleteDirectory(logDir);
            }
            logDir.mkdir();
        }
        EmbeddedUtils.startServer(config);
    }
    
    @AfterClass
    public static void tearDownLdap()
    {
        stopLdapServer();
    }
    
    protected static void stopLdapServer()
    {
        if(!EmbeddedUtils.isRunning())
        {
            return;
        }
        EmbeddedUtils.stopServer(null, null);
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testLdapSaslSecurityRealm_Success()
    {
        // Supports DIGEST-MD5
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNotNull(user);
            assertEquals("test1", user.getUsername());
            assertEquals("", user.getPassword());
            assertNull(user.getDn());
            assertTrue(user.isEnabled());
            assertTrue(user.isAccountNonExpired());
            assertTrue(user.isAccountNonLocked());
            assertTrue(user.isCredentialsNonExpired());
            assertEquals(0, user.getAuthorities().length);
        }
        
        // Supports CRAM-MD5
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "CRAM-MD5",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            UserDetails user = target.authenticate("test2", "password2");
            assertNotNull(user);
        }
        
        // Specifying non-exist mechanism and exist mechanism
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "NOSUCHMETHOD DIGEST-MD5",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            UserDetails user = target.authenticate("test1", "password1");
            assertNotNull(user);
        }
        
        // Specifying invalid dn
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=nosuchdc,dc=com", ldapPort)
                            ),
                    "NOSUCHMETHOD DIGEST-MD5",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            UserDetails user = target.authenticate("test1", "password1");
            assertNotNull(user);
        }
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testLdapSaslSecurityRealm_Failure()
    {
        // Invalid credential
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("Not reachable", false);
            }
            catch(BadCredentialsException e)
            {
                assertTrue(true);
            }
        }
        
        // No valid URI
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    new ArrayList<String>(),
                    "DIGEST-MD5",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("Not reachable", false);
            }
            catch(AuthenticationServiceException e)
            {
                assertTrue(true);
            }
        }
        
        // No valid mechanism
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("Not reachable", false);
            }
            catch(AuthenticationServiceException e)
            {
                assertTrue(true);
            }
        }
        
        // Bad mechanism
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "NOSUCHMETHOD",
                    new NoUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("Not reachable", false);
            }
            catch(AuthenticationServiceException e)
            {
                assertTrue(true);
            }
        }
    }
    
    @Test
    @For(LdapWhoamiUserDnResolver.class)
    public void testLdapWhoamiUserDnResolver_Success()
    {
        // LDAP who am i succeeded.
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new LdapWhoamiUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
    }
    
    @Test
    @For(LdapWhoamiUserDnResolver.class)
    public void testLdapWhoamiUserDnResolver_Failure() throws Exception
    {
        // LDAP who am i is not allowed.
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new LdapWhoamiUserDnResolver(),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test3", "password3");
            assertNull(user.getDn());
        }
        
        // LDAP who am i is not supported.
        {
            try{
                // Restart the server not to support LDAP who am i.
                startLdapServer("config_nowhoami.ldif");
                
                LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                        Arrays.asList(
                                String.format("ldap://127.0.0.1:%d/", ldapPort)
                                ),
                        "DIGEST-MD5",
                        new LdapWhoamiUserDnResolver(),
                        new NoGroupResolver(),
                        0,
                        3000
                        );
                
                LdapUser user = (LdapUser)target.authenticate("test1", "password1");
                assertNull(user.getDn());
            }
            finally
            {
                startLdapServer("config.ldif");
            }
        }
    }
    
    @Test
    @For(SearchUserDnResolver.class)
    public void testSearchUserDnResolver_Success()
    {
        // Success
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new SearchUserDnResolver("dc=example,dc=com", "uid={0}"),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // Success(other than uid)
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new SearchUserDnResolver("dc=example,dc=com", "sn={0}"),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test2", "password2");
            assertEquals("cn=User3,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // Specifying searchbase in URI
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=example,dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new SearchUserDnResolver("", "uid={0}"),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // Specifying searchbase in URI and parameter
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new SearchUserDnResolver("dc=example", "uid={0}"),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // No searchbase
        {
            LdapSaslSecurityRealm target = new MockLdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    new SearchUserDnResolver("", "uid={0}"),
                    new NoGroupResolver(),
                    0,
                    3000
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
    }
}
