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

import javax.naming.ldap.LdapContext;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Hudson;

/**
 * Resolve the user DN in a SASL authenticated session.
 * Abstract class.
 */
public abstract class UserDnResolver extends
        AbstractDescribableImpl<UserDnResolver>
{
    /**
     * Returns the User DN.
     * 
     * @param ctx LDAP context, already authenticated.
     * @param username the username the user authenticated with.
     * 
     * @return the DN of the user.
     */
    abstract public String getUserDn(LdapContext ctx, String username);
    
    /**
     * Returns all the UserDnResolver subclass whose DescriptorImpl is annotated with Extension.
     * @return DescriptorExtensionList of UserDnResolver subclasses.
     */
    static public DescriptorExtensionList<UserDnResolver,Descriptor<UserDnResolver>> all()
    {
        return Hudson.getInstance().<UserDnResolver,Descriptor<UserDnResolver>>getDescriptorList(UserDnResolver.class);
    }
}
