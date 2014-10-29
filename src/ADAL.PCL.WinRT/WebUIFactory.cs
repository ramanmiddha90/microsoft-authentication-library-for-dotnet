﻿//----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

using System;
using System.Net;
using System.Threading.Tasks;

using Windows.System.Threading;

namespace Microsoft.IdentityModel.Clients.ActiveDirectory
{
    internal class WebUIFactory : IWebUIFactory
    {
        public IWebUI CreateAuthenticationDialog(IAuthorizationParameters parameters)
        {
            return new WebUI(parameters);
        }

        public async Task<IHttpWebResponse> GetResponseWithTimeoutSyncOrAsync(HttpWebRequest request, int timeoutInMilliSeconds, CallState callState)
        {
            var timer = Windows.System.Threading.ThreadPoolTimer.CreateTimer(
                            delegate
                            {
                                request.Abort();
                            },
                            TimeSpan.FromMilliseconds(timeoutInMilliSeconds));

            try
            {
                return PlatformPlugin.HttpWebRequestFactory.CreateResponse(await request.GetResponseAsync());
            }
            finally
            {
                timer.Cancel();
            }
        }       
    }
}