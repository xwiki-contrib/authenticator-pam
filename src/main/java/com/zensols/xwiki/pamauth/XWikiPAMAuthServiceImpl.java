/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.zensols.xwiki.pamauth;

import java.security.Principal;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.context.Execution;
import org.xwiki.context.ExecutionContext;
import org.xwiki.security.authentication.UserAuthenticatedEventNotifier;
import org.xwiki.text.StringUtils;


/**
 * Implementation of the PAM authorization module.
 *
 * @version $Id$
 */
public class XWikiPAMAuthServiceImpl extends XWikiAuthServiceImpl
{
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiPAMAuthServiceImpl.class);

    private static final String CONTEXT_CONFIGURATION = "pam.configuration";
    private static final String PAM_REMOTE_ATTRIBUTE = "pam.remoteuser";
    private static final String PAM_MESSAGE_PROP = "message";

    private final ConcurrentMap<String, String> lockMap = new ConcurrentHashMap<>();
    private Execution execution;

    private UserAuthenticatedEventNotifier notifier;

    private UserAuthenticatedEventNotifier getNotifier()
    {
        if (this.notifier == null) {
            this.notifier = Utils.getComponent(UserAuthenticatedEventNotifier.class);
        }

        return this.notifier;
    }
    protected XWikiPAMConfig initConfiguration(String authInput)
    {
        ExecutionContext econtext = getExecutionContext();

        if (econtext != null) {
            XWikiPAMConfig configuration = new XWikiPAMConfig(authInput);
            econtext.setProperty(CONTEXT_CONFIGURATION, configuration);
            return configuration;
        }

        return new XWikiPAMConfig(null);
    }

    protected ExecutionContext getExecutionContext()
    {
        if (this.execution == null) {
            this.execution = Utils.getComponent(Execution.class);
        }

        return this.execution.getContext();
    }

    protected XWikiPAMConfig getConfiguration(String userId)
    {
        ExecutionContext econtext = getExecutionContext();

        if (econtext != null) {
            XWikiPAMConfig configuration = (XWikiPAMConfig) econtext.getProperty(CONTEXT_CONFIGURATION);

            if (configuration != null) {
                return configuration;
            }
        }

        return new XWikiPAMConfig(userId);
    }

    protected void removeConfiguration()
    {
        ExecutionContext econtext = getExecutionContext();

        if (econtext != null) {
            econtext.removeProperty(CONTEXT_CONFIGURATION);
        }
    }

    private Principal checkSessionPrincipal(String remoteUser, XWikiRequest request)
    {
        // Get the current user
        Principal principal =
            (Principal) request.getSession().getAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY);

        if (principal != null)
        {
            String storedRemoteUser = (String) request.getSession().getAttribute(PAM_REMOTE_ATTRIBUTE);

            // If the remote user changed authenticate again
            if (remoteUser.equals(storedRemoteUser)) {
                return principal;
            }
        }

        return null;
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        String httpHeader = getConfiguration(null).getHttpHeader();
        XWikiUser user = null;
        String remoteUser;

        if (StringUtils.isEmpty(httpHeader)) {
            remoteUser = context.getRequest().getRemoteUser();
        } else {
            remoteUser = context.getRequest().getHeader(httpHeader);
        }

        if (remoteUser != null) {
            LOGGER.debug("REMOTE_USER: {}", remoteUser);
            user = checkAuthSSO(remoteUser, context);
        }

        if (user == null) {
            user = super.checkAuth(context);
        }

        LOGGER.debug("XWikiUser: {}", user);

        return user;
    }

    private XWikiUser checkAuthSSO(String remoteUser, XWikiContext context)
    {
        XWikiRequest request = context.getRequest();

        // Check if the user is already authenticated
        Principal principal = checkSessionPrincipal(remoteUser, request);

        XWikiUser user;

        if (principal == null) {
            // Authenticate
            principal = checkAuthSSOSync(remoteUser, request, context);
            if (principal == null) {
                return null;
            }

            // Remember user in the session
            request.getSession().setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);
            request.getSession().setAttribute(PAM_REMOTE_ATTRIBUTE, context.getRequest().getRemoteUser());

            // Notify about this new authentication
            getNotifier().notify(principal.getName());

            user = new XWikiUser(principal.getName());
        } else {
            user = new XWikiUser(principal.getName().startsWith(context.getWikiId())
                ? principal.getName().substring(context.getWikiId().length() + 1) : principal.getName());
        }

        LOGGER.debug("XWikiUser = [{}]", user);

        removeConfiguration();

        return user;
    }

    private Principal checkAuthSSOSync(String remoteUser, XWikiRequest request, XWikiContext context)
    {
        String lock = this.lockMap.putIfAbsent(remoteUser, remoteUser);
        if (lock == null) {
            lock = this.lockMap.get(remoteUser);
        }
        synchronized (lock) {
            // Check if the user was authenticated by another thread in the meantime
            Principal principal = checkSessionPrincipal(remoteUser, request);

            if (principal == null) {
                // Authenticate
                principal = pamAuthenticate(remoteUser, null, true, false, context);
            }

            return principal;
        }
    }

    /**
     * Try both local and global pam login and return {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param password the password of the user to log in.
     * @param trusted is it a trusted authentication (should the credentials be validated)
     * @param compactPrincipal if true the user principal should not contain the wiki in case of local authentication
     * @param context the XWiki context.
     * @return the {@link Principal}.
     */
    private Principal pamAuthenticate(String userId, String password, boolean trusted, boolean compactPrincipal,
        XWikiContext context)
    {
        Principal principal = null;

        // First we check in the local context for a valid pam user
        try {
            principal = pamAuthenticateInContext(userId, null, password, trusted, context, compactPrincipal);
        } catch (Exception e) {
            // continue
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Local PAM authentication failed.", e);
            }
        }

        // If local pam failed, try global pam
        if (principal == null && !context.isMainWiki()) {
            // Then we check in the main database
            String db = context.getWikiId();
            try {
                context.setWikiId(context.getMainXWiki());
                try {
                    principal = pamAuthenticateInContext(userId, null, password, trusted, context, false);
                } catch (Exception e) {
                    // continue
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Global PAM authentication failed.", e);
                    }
                }
            } finally {
                context.setWikiId(db);
            }
        }

        return principal;
    }

    /**
     * Try both local and global DB login if trylocal is true {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param pamPassword the password of the user to log in.
     * @param context the XWiki context.
     * @return the {@link Principal}.
     * @throws XWikiException error when checking user name and password.
     */
    protected Principal xwikiAuthenticate(String userId, String pamPassword, XWikiContext context)
        throws XWikiException
    {
        Principal principal = null;

        String trylocal = getConfiguration(userId).getPAMParam("pam_trylocal", "0");

        if ("1".equals(trylocal)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Trying authentication against XWiki DB");
            }

            principal = super.authenticate(userId, pamPassword, context);
        }

        return principal;
    }

    @Override
    public Principal authenticate(String userId, String password, XWikiContext context) throws XWikiException
    {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Starting PAM authentication");
        }

        /*
         * TO DO: Put the next 4 following "if" in common with XWikiAuthService to ensure coherence This method was
         * returning null on failure so I preserved that behaviour, while adding the exact error messages to the context
         * given as argument. However, the right way to do this would probably be to throw XWikiException-s.
         */

        if (userId == null) {
            // If we can't find the username field then we are probably on the login screen

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("The provided user is null."
                    + " We don't try to authenticate, it probably means the user is in non logged mode.");
            }

            return null;
        }

        // Check for empty usernames
        if (userId.equals("")) {
            context.put(PAM_MESSAGE_PROP, "nousername");

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PAM authentication failed: login empty");
            }

            return null;
        }

        // Check for empty passwords
        if ((password == null) || (password.trim().equals(""))) {
            context.put(PAM_MESSAGE_PROP, "nopassword");

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PAM authentication failed: password null or empty");
            }

            return null;
        }

        // Check for superadmin
        if (isSuperAdmin(userId)) {
            return authenticateSuperAdmin(password, context);
        }

        // Try authentication against pam
        Principal principal = pamAuthenticate(userId, password, false, true, context);

        if (principal == null) {
            // Fallback to local DB only if trylocal is true
            principal = xwikiAuthenticate(userId, password, context);
        }

        if (LOGGER.isDebugEnabled()) {
            if (principal != null) {
                LOGGER.debug("PAM authentication succeed with principal [{}]", principal.getName());
            } else {
                LOGGER.debug("PAM authentication failed for user [{}]", userId);
            }
        }

        removeConfiguration();

        return principal;
    }

    /**
     * Try PAM login for given context and return {@link Principal}.
     * 
     * @param userNameRaw the user name (not uid) of the UNIX user
     * @param validXWikiUserName the name of the XWiki user to log in.
     * @param password the password of the user to log in.
     * @param trusted true in case of trusted authentication (i.e. should the credentials be validated or not)
     * @param context the XWiki context.
     * @param local indicate if it's a local authentication. Supposed to return a local user {@link Principal} (without
     *            the wiki name).
     * @return the {@link Principal}.
     * @throws XWikiException for failed logins
     * @since 9.0
     */
    protected Principal pamAuthenticateInContext(String userNameRaw, String validXWikiUserName, String password,
                                                 boolean trusted, XWikiContext context, boolean local)
        throws XWikiException
    {
        Principal principal = null;
        String userName = userNameRaw.trim();
        XWikiPAMConfig configuration = initConfiguration(userName);
        String passwd = password;

        if (!configuration.isPAMEnabled()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PAM authentication failed: PAM not active");
            }
        } else {
            XWikiPAMUtils pamUtils = new XWikiPAMUtils(configuration);
            XWikiDocument userProfile = pamUtils.getUserProfileByUserName(validXWikiUserName, userName, context);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PAM authentication on xwikName: {}, userName: {}, with profile: {}",
                             validXWikiUserName, userName, userProfile);
            }

            if (trusted)
            {
                passwd = null;
            }
            userProfile = pamUtils.syncUser(userProfile, userName, passwd, context);

            if (userProfile == null) {
                throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                                         "PAM authentication failed: could not validate the password: "
                                         + "wrong password for " + userName);
            }

            if (local) {
                principal = new SimplePrincipal(userProfile.getFullName());
            } else {
                principal = new SimplePrincipal(userProfile.getPrefixedFullName());
            }
        }

        return principal;
    }
}
