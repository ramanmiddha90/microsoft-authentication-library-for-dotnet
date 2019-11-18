// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace DesktopTestApp
{
    class PublicClientHandler
    {
        private readonly string _clientName = "DesktopTestApp";

        public PublicClientHandler(string clientId, LogCallback logCallback)
        {
            ApplicationId = clientId;
            PublicClientApplication = PublicClientApplicationBuilder.Create(ApplicationId)
                .WithClientName(_clientName)
                .WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient")
                .WithLogging(logCallback, LogLevel.Verbose, true)
                //.WithTenantId("72f988bf-86f1-41af-91ab-2d7cd011db47")
                //.WithTenantId("0287f963-2d72-4363-9e3a-5705c5b0f031")
                //.WithTenantId("f645ad92-e38d-4d1a-b510-d1b09a74a8ca")
#if ARIA_TELEMETRY_ENABLED
                .WithTelemetry((new Microsoft.Identity.Client.AriaTelemetryProvider.ServerTelemetryHandler()).OnEvents)
#endif
                .BuildConcrete();


            //CreateOrUpdatePublicClientApp(InteractiveAuthority, ApplicationId);
        }

        public string ApplicationId { get; set; }
        public string InteractiveAuthority { get; set; }
        public string AuthorityOverride { get; set; }
        public string ExtraQueryParams { get; set; }
        public string LoginHint { get; set; }
        public IAccount CurrentUser { get; set; }
        public PublicClientApplication PublicClientApplication { get; set; }

        public async Task<AuthenticationResult> AcquireTokenInteractiveAsync(
            IEnumerable<string> scopes,
            Prompt uiBehavior,
            string extraQueryParams)
        {
            //CreateOrUpdatePublicClientApp(InteractiveAuthority, ApplicationId);

            AuthenticationResult result;
            if (CurrentUser != null)
            {
                result = await PublicClientApplication
                    .AcquireTokenInteractive(scopes)
                    .WithLoginHint(LoginHint)
                    .WithAccount(CurrentUser)
                    .WithPrompt(uiBehavior)
                    .WithExtraQueryParameters(extraQueryParams)
                    .ExecuteAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            else
            {
                result = await PublicClientApplication
                    .AcquireTokenInteractive(scopes)
                    .WithLoginHint(LoginHint)
                    .WithPrompt(uiBehavior)
                    .WithExtraQueryParameters(extraQueryParams)
                    .ExecuteAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            CurrentUser = result.Account;

            return result;
        }

        public async Task<AuthenticationResult> AcquireTokenInteractiveWithAuthorityAsync(
            IEnumerable<string> scopes,
            Prompt uiBehavior,
            string extraQueryParams)
        {
            CreateOrUpdatePublicClientApp(InteractiveAuthority, ApplicationId);

            AuthenticationResult result;
            if (CurrentUser != null)
            {
                result = await PublicClientApplication
                    .AcquireTokenInteractive(scopes)
                    .WithAccount(CurrentUser)
                    .WithPrompt(uiBehavior)
                    .WithExtraQueryParameters(extraQueryParams)
                    .WithAuthority(AuthorityOverride)
                    .ExecuteAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            else
            {
                result = await PublicClientApplication
                    .AcquireTokenInteractive(scopes)
                    .WithLoginHint(LoginHint)
                    .WithPrompt(uiBehavior)
                    .WithExtraQueryParameters(extraQueryParams)
                    .WithAuthority(AuthorityOverride)
                    .ExecuteAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }

            CurrentUser = result.Account;
            return result;
        }

        public async Task<AuthenticationResult> AcquireTokenSilentAsync(IEnumerable<string> scopes, bool forceRefresh)
        {
            var builder = PublicClientApplication
                .AcquireTokenSilent(scopes, "jeferrie@msdevex.onmicrosoft.com")
                .WithForceRefresh(forceRefresh);

            if (!string.IsNullOrWhiteSpace(AuthorityOverride))
            {
                builder = builder.WithAuthority(AuthorityOverride);
            }

            return await builder.ExecuteAsync(CancellationToken.None).ConfigureAwait(false);
        }

        public async Task<AuthenticationResult> AcquireTokenInteractiveWithB2CAuthorityAsync(
          IEnumerable<string> scopes,
          Prompt uiBehavior,
          string extraQueryParams,
          string b2cAuthority)
        {
            CreateOrUpdatePublicClientApp(b2cAuthority, ApplicationId);
            AuthenticationResult result;
            result = await PublicClientApplication
                   .AcquireTokenInteractive(scopes)
                   .WithAccount(CurrentUser)
                   .WithPrompt(uiBehavior)
                   .WithExtraQueryParameters(extraQueryParams)
                   .WithB2CAuthority(b2cAuthority)
                   .ExecuteAsync(CancellationToken.None)
                   .ConfigureAwait(false);

            CurrentUser = result.Account;
            return result;
        }

        public void CreateOrUpdatePublicClientApp(string interactiveAuthority, string applicationId)
        {
            var builder = PublicClientApplicationBuilder
                .Create(ApplicationId)
                .WithClientName(_clientName);

            if (!string.IsNullOrWhiteSpace(interactiveAuthority))
            {
                // Use the override authority provided
                builder = builder.WithAuthority(new Uri(interactiveAuthority), true);
            }

            PublicClientApplication = builder.BuildConcrete();

            PublicClientApplication.UserTokenCache.SetBeforeAccess(TokenCacheHelper.BeforeAccessNotification);
            PublicClientApplication.UserTokenCache.SetAfterAccess(TokenCacheHelper.AfterAccessNotification);
        }
    }
}
