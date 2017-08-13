using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OwinExsample.Extensions
{
    public static class OAuthContextExtension
    {
        public static string GetUserId(this IOwinContext ctx)
        {
            var result = "-1";
            var claim = ctx.Authentication.User.Claims.FirstOrDefault(p => p.Type == "UserId");
            if(claim != null)
            {
                result = claim.Value;
            }

            return result;
        }

    }
}