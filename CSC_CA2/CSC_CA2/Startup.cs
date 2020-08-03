using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Hosting;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(CSC_CA2.Startup))]

namespace CSC_CA2
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);

        }
    }
}
