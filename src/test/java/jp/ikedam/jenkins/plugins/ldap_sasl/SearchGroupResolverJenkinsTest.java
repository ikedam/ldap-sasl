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
 * Tests for SearchGroupResolver, concerned with Jenkins
 */
public class SearchGroupResolverJenkinsTest
{
    @Rule
    public JenkinsRule j = new JenkinsRule();
    
    private SearchGroupResolver.DescriptorImpl getDescriptor()
    {
        return (SearchGroupResolver.DescriptorImpl)new SearchGroupResolver(null, null).getDescriptor();
        //return new SearchGroupResolver.DescriptorImpl();
    }
    
    @Test
    public void DescriptorDoCheckSearchBase_Success()
    {
        SearchGroupResolver.DescriptorImpl descriptor = getDescriptor();
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
    public void DescriptorDoCheckSearchBase_Failure()
    {
        SearchGroupResolver.DescriptorImpl descriptor = getDescriptor();
        // invalid format
        {
            assertEquals("invalid format",
                    FormValidation.Kind.ERROR,
                    descriptor.doCheckSearchBase("hogehoge").kind
                    );
        }
    }
    
    @Test
    public void DescriptorDoCheckPrefix_Success()
    {
        SearchGroupResolver.DescriptorImpl descriptor = getDescriptor();
        // simple value
        {
            assertEquals("simple value",
                    FormValidation.Kind.OK,
                    descriptor.doCheckPrefix("ROLE_").kind
                    );
        }
        
        // null
        {
            assertEquals("null",
                    FormValidation.Kind.OK,
                    descriptor.doCheckPrefix(null).kind
                    );
        }
        
        // empty
        {
            assertEquals("empty",
                    FormValidation.Kind.OK,
                    descriptor.doCheckPrefix("").kind
                    );
        }
        
        // blank
        {
            assertEquals("blank",
                    FormValidation.Kind.OK,
                    descriptor.doCheckPrefix("  ").kind
                    );
        }
    }
    
    @Test
    public void DescriptorDoCheckPrefix_Failure()
    {
        // Nothing to do
    }
    
    
}
