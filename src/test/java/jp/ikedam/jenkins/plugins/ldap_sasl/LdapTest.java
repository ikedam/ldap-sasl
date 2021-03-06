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
import java.util.ArrayList;
import java.util.Arrays;

import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.For;
import org.jvnet.hudson.test.JenkinsRule;
import org.opends.server.types.DirectoryEnvironmentConfig;
import org.opends.server.util.EmbeddedUtils;

import static org.junit.Assert.*;

/**
 * Test using LDAP.
 */
public class LdapTest
{
    @Rule
    public JenkinsRule j = new JenkinsRule();
    
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
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNotNull("Using DIGEST-MD5", user);
            assertEquals("Using DIGEST-MD5", "test1", user.getUsername());
            assertEquals("Using DIGEST-MD5", "", user.getPassword());
            assertNull("Using DIGEST-MD5", user.getDn());
            assertTrue("Using DIGEST-MD5", user.isEnabled());
            assertTrue("Using DIGEST-MD5", user.isAccountNonExpired());
            assertTrue("Using DIGEST-MD5", user.isAccountNonLocked());
            assertTrue("Using DIGEST-MD5", user.isCredentialsNonExpired());
            assertEquals("Using DIGEST-MD5", 0, user.getAuthorities().length);
        }
        
        // Supports CRAM-MD5
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "CRAM-MD5",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            UserDetails user = target.authenticate("test2", "password2");
            assertNotNull("Using CRAM-MD5", user);
        }
        
        // Specifying non-exist mechanism and exist mechanism
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "NOSUCHMETHOD DIGEST-MD5",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            UserDetails user = target.authenticate("test1", "password1");
            assertNotNull("Specify unavailable mechanism and available mechanism", user);
        }
        
        // Specifying non-exist dn
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=nosuchdc,dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            UserDetails user = target.authenticate("test1", "password1");
            assertNotNull("Specifying non-exist dn", user);
        }
        
        // work with null resolvers
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=nosuchdc,dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            UserDetails user = target.authenticate("test1", "password1");
            assertNotNull("work with null resolvers", user);
        }
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testLdapSaslSecurityRealm_Failure()
    {
        // Invalid credential
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("Invalid credential: Not reachable", false);
            }
            catch(BadCredentialsException e)
            {
                assertTrue("Invalid credential", true);
            }
        }
        
        // No valid URI
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    new ArrayList<String>(),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("No valid URI: Not reachable", false);
            }
            catch(AuthenticationServiceException e)
            {
                assertTrue("No valid URI", true);
            }
        }
        
        // No valid mechanism
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("No valid mechanism: Not reachable", false);
            }
            catch(AuthenticationServiceException e)
            {
                assertTrue("No valid mechanism", true);
            }
        }
        
        // unavailable mechanism
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "NOSUCHMETHOD",
                    0,
                    3000,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            try
            {
                target.authenticate("test1", "baddpassword");
                assertTrue("unavailable mechanism: Not reachable", false);
            }
            catch(AuthenticationServiceException e)
            {
                assertTrue("unavailable mechanism", true);
            }
        }
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testLdapSaslSecurityRealm_loadUserByUsernameSuccess()
    {
        LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                Arrays.asList(
                        String.format("ldap://127.0.0.1:%d/", ldapPort)
                        ),
                "DIGEST-MD5",
                0,
                3000,
                "dc=example,dc=com",
                "uid=${uid}",
                "dc=example,dc=com",
                null,
                "test3",
                "password3"
                );
        LdapUser user = (LdapUser)target.loadUserByUsername("test1");
        assertEquals("cn=User1,ou=People,dc=example,dc=com", user.getDn());
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testLdapSaslSecurityRealm_loadUserByUsernameNotFound()
    {
        LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                Arrays.asList(
                        String.format("ldap://127.0.0.1:%d/", ldapPort)
                        ),
                "DIGEST-MD5",
                0,
                3000,
                "dc=example,dc=com",
                "uid=${uid}",
                "dc=example,dc=com",
                null,
                "test3",
                "password3"
                );
        LdapUser user = (LdapUser)target.loadUserByUsername("nosuchuser");
        assertNull(user);
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testLdapSaslSecurityRealm_loadUserByUsernameFailure()
    {
        LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                Arrays.asList(
                        String.format("ldap://127.0.0.1:%d/", ldapPort)
                        ),
                "DIGEST-MD5",
                0,
                3000,
                "dc=example,dc=com",
                "uid=${uid}",
                "dc=example,dc=com",
                null,
                null,
                null
                );
        LdapUser user = (LdapUser)target.loadUserByUsername("test1");
        assertNull(user);
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testLdapSaslSecurityRealm_loadGroupByGroupname()
    {
        LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                Arrays.asList(
                        String.format("ldap://127.0.0.1:%d/", ldapPort)
                        ),
                "DIGEST-MD5",
                0,
                3000,
                null,
                null,
                null,
                null,
                null,
                null
                );
        assertNull(target.loadGroupByGroupname("Group1"));
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testSearchUserDnResolver_Success()
    {
        // Success
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Query for user", "cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // Success(other than uid)
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "sn=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test2", "password2");
            assertEquals("Query for user using other than uid", "cn=User3,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // Specifying searchbase in URI
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=example,dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "",
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Specifying searchbase in URI", "cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // Specifying searchbase in URI and parameter
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example",
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Specifying searchbase in URI and parameter", "cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // No searchbase
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("No searchbase", "cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // No parameter holder in query template
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    "uid=test2",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("No parameter holder in query template", "cn=User2,ou=People,dc=example,dc=com", user.getDn());
        }
        
        // Complicated query
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "(| (& (objectClass=inetOrgPerson) (uid=${uid})) (& (objectClass=person) (uid=${uid})))",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Complicated query", "cn=User1,ou=People,dc=example,dc=com", user.getDn());
        }
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testSearchUserDnResolver_Failure()
    {
        // No match
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "cn=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("No match", user.getDn());
        }
        
        // More than one match
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "objectClass=inetOrgPerson",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("More than one match", user.getDn());
        }
        
        // Non exist DN(specified as a parameter)
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=jp",
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("Non exist DN(specified as a parameter)", user.getDn());
        }
        
        // Non exist DN(specified in URI)
        {
            // Suppress severe log
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=example,dc=jp", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("Non exist DN(specified in URI)", user.getDn());
        }
        
        // Invalid DN
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=example,dc=jp", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "hogehoge",
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("Invalid DN", user.getDn());
        }
        
        // No query(null)
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    null,
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("No query(null)", user.getDn());
        }
        
        // No query(empty)
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "  ",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("No query(empty)", user.getDn());
        }
        
        // Bad query
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "hogehoge",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertNull("Bad query", user.getDn());
        }
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testSearchGroupResolver_Success()
    {
        // Success
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    "dc=example,dc=com",
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Query for group", 4, user.getAuthorities().length);
            assertTrue("Query for group", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group1")));
            assertFalse("Query for group", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group2")));
            assertTrue("Query for group", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group3")));
            assertTrue("Query for group", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup1")));
            assertFalse("Query for group", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup2")));
            assertTrue("Query for group", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup3")));
        }
        
        // Specifying prefix
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    "dc=example,dc=com",
                    "ROLE_",
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test2", "password2");
            assertEquals("Specifying prefix", 4, user.getAuthorities().length);
            assertTrue("Specifying prefix", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("ROLE_Group2")));
            assertTrue("Specifying prefix", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("ROLE_Group3")));
            assertTrue("Specifying prefix", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("ROLE_UniqueGroup2")));
            assertTrue("Specifying prefix", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("ROLE_UniqueGroup3")));
        }
        
        // Specifying DN in URI
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=example,dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    "uid=${uid}",
                    "",
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Specifying DN in URI", 4, user.getAuthorities().length);
            assertTrue("Specifying DN in URI", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group1")));
            assertTrue("Specifying DN in URI", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group3")));
            assertTrue("Specifying DN in URI", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup1")));
            assertTrue("Specifying DN in URI", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup3")));
        }
        
        // No DN
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("No DN", 4, user.getAuthorities().length);
            assertTrue("No DN", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group1")));
            assertTrue("No DN", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group3")));
            assertTrue("No DN", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup1")));
            assertTrue("No DN", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup3")));
        }
        
        // Specifying DN both in URI and parameter
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=com", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example",
                    "uid=${uid}",
                    "dc=example",
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Specifying DN both in URI and parameter", 4, user.getAuthorities().length);
            assertTrue("Specifying DN both in URI and parameter", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group1")));
            assertTrue("Specifying DN both in URI and parameter", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("Group3")));
            assertTrue("Specifying DN both in URI and parameter", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup1")));
            assertTrue("Specifying DN both in URI and parameter", Arrays.asList(user.getAuthorities()).contains(new GrantedAuthorityImpl("UniqueGroup3")));
        }
        
        // No Group
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    "dc=example,dc=com",
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test3", "password3");
            assertEquals("No Group", 0, user.getAuthorities().length);
        }
    }
    
    @Test
    @For(LdapSaslSecurityRealm.class)
    public void testSearchGroupResolver_Failure()
    {
        // User is not resolved
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    null,
                    null,
                    "dc=example,dc=com",
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("User is not resolved", 0, user.getAuthorities().length);
        }
        
        // Non-exist DN specified in parameter
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    "dc=example,dc=jp",
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Non-exist DN specified in parameter", 0, user.getAuthorities().length);
        }
        
        // Non-exist DN specified in URI
        {
            // Suppress warning log
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/dc=example,dc=jp", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    null,
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Non-exist DN specified in URI", 0, user.getAuthorities().length);
        }
        
        // Invalid DN
        {
            LdapSaslSecurityRealm target = new LdapSaslSecurityRealm(
                    Arrays.asList(
                            String.format("ldap://127.0.0.1:%d/", ldapPort)
                            ),
                    "DIGEST-MD5",
                    0,
                    3000,
                    "dc=example,dc=com",
                    "uid=${uid}",
                    "hogehoge",
                    null,
                    null,
                    null
                    );
            
            LdapUser user = (LdapUser)target.authenticate("test1", "password1");
            assertEquals("Invalid DN", 0, user.getAuthorities().length);
        }
    }
}
