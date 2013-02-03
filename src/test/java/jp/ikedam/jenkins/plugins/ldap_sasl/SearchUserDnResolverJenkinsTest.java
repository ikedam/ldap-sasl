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

import hudson.util.FormValidation;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.*;

/**
 * Tests for SearchUserDnResolver concerned with Jenkins
 */
public class SearchUserDnResolverJenkinsTest
{
    @Rule
    public JenkinsRule j = new JenkinsRule();
    
    private SearchUserDnResolver.DescriptorImpl getDescriptor()
    {
        //return new SearchUserDnResolver(null, null).getDescriptor();
        return new SearchUserDnResolver.DescriptorImpl();
    }
    
    @Test
    public void testDescriptorDoCheckSearchBase_Success()
    {
        SearchUserDnResolver.DescriptorImpl descriptor = getDescriptor();
        // null
        {
            assertEquals("null",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchBase(null).kind
                    );
        }
        
        // empty
        {
            assertEquals("empty",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchBase("").kind
                    );
        }
        
        // blank
        {
            assertEquals("blank",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchBase("  ").kind
                    );
        }
        
        // proper DN
        {
            assertEquals("proper DN",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchBase("dc=example,dc=com").kind
                    );
        }
        
        // surrounded with spaces
        {
            assertEquals("surrounded with spaces",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchBase("  dc=example,dc=com  ").kind
                    );
        }
    }
    
    @Test
    public void testDescriptorDoCheckSearchBase_Failure()
    {
        SearchUserDnResolver.DescriptorImpl descriptor = getDescriptor();
        // invalid format
        {
            assertEquals("invalid format",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchBase("hogehoge").kind
                    );
        }
    }
    
    @Test
    public void testDoCheckSearchQueryTemplate_Success()
    {
        SearchUserDnResolver.DescriptorImpl descriptor = getDescriptor();
        
        // contains a place holder
        {
            assertEquals("contains a place holder",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchQueryTemplate("uid={0}").kind
                    );
        }
        
        // contains multiple holders
        {
            assertEquals("contains multiple holders",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchQueryTemplate("(| (uid={0}) (uid={0}))").kind
                    );
        }
        
        // invalid format(not checked)
        {
            assertEquals("invalid format(not checked)",
                    FormValidation.Kind.OK,
                    descriptor.doCheckSearchQueryTemplate("((({0}").kind
                    );
        }
    }
    
    @Test
    public void testDoCheckSearchQueryTemplate_Failure()
    {
        SearchUserDnResolver.DescriptorImpl descriptor = getDescriptor();
        // null
        {
            assertEquals("null",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchQueryTemplate(null).kind
                    );
        }
        
        // empty
        {
            assertEquals("empty",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchQueryTemplate("").kind
                    );
        }
        
        // blank
        {
            assertEquals("blank",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchQueryTemplate("  ").kind
                    );
        }
        
        // contains no holder
        {
            assertEquals("contains no holder",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchQueryTemplate("uid=hogehoge").kind
                    );
        }
        
        // contains non usable holder
        {
            assertEquals("contains non usable holder",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchQueryTemplate("uid={1}").kind
                    );
        }
        
        // Bad Message Format
        {
            assertEquals("Bad Message Format",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchQueryTemplate("{{0}}").kind
                    );
        }
    }
}
