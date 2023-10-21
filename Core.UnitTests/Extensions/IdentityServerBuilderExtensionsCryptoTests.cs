// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdNet8;
using IdNet8.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;
using Xunit;

namespace IdentityServer.UnitTests.Extensions
{
    public class IdentityServerBuilderExtensionsCryptoTests
    {
        [Fact]
        public void AddSigningCredential_with_json_web_key_containing_asymmetric_key_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            IdentityModelEventSource.ShowPII = true;

            String json = 
            @"{
                ""p"": ""-jJ7pclTFvEmlDxJe5QQsnj2ySZrYHYskdu4McrcSXugGp1ZY8PiO20CrH4p_I0jCavwYJrx4v3t23izZlBkK0rqFD5js185h99nOOIosz99lgcvwaumtMgRiTZErS7W5_AAk_cVt5JEHdDF8nQoGQjUIr34hEtyi8c809bl2Gk"",
                ""kty"": ""RSA"",
                ""q"": ""soOd8lhNIeLDfEFIPDndYFi9DgbXmZvWTXAesTTKsfmv5O6KyZTv5-9l6ZBSYA1s5PZvjWSUuZ0sbh3IQvun3t95cDApmnAJvL_HGxOigXsAggjUowR8PfkDHo3N2YFGAJFPlHSkJz3pSw5dSCavreTIsCpeEeZA3177Z2d0xO0"",
                ""d"": ""S7HjUJONfLjCaqNKw_u2IkzyX8ERC35Uq7SV-UElhtjRZdUe6R15d5olFyxiWFYXL6fDn_iE-5RIvKyGKI6LnfxeW_OWASZBQTJpiQJ8bzjJmUuBq193jjTFvAWPqLOTKvMUi111FeeDg3wCqzkbR-R5NgF51wN_6Xz7WJE0Vdvc2mHjh_Ox8fSy2Fq8JAP92V8PK8G5cgVnXR9GfKWXabiWrP7FnldA88OPjZ8qbx2HObDI-MS9TW8BARi4QfmGeOYQ2TU1H17SNXotTvz7IxhCrT0r0QwuUPnm1wAhwO2u68pmusYshqLnuahivagLZy6n5zpsOiBqNbjMEaldwQ"",
                ""e"": ""AQAB"",
                ""use"": ""sig"",
                ""kid"": ""BwfcZ9NAqyzTaynCnFz4cjpQ1LRQaAq0cYmjJTQJRig"",
                ""qi"": ""zczgEczL2-3AyQ-OlyQJLuHeoOq2j3445DkgIXgdMb3gQKOcZHS-u1M8wvOkLmK5bV0BDeUD0ockRqqRD0Eth2B9-ajhhtiBdWtHd-0gf1E8F2ZH8SpW5EAQU9t8PESxYB3gg5cVz9fS1pTl8tnBf9yoLCqxEJmKrrRfGT-9MbY"",
                ""dp"": ""AfB6POK-niLoZaXB_A89weRmJVEC7BB-b_MADoLACmHG7-3gT4GpM0S5DJU9xhNh_iUzC8ynq1bEjTr2SQi-fgdqoRWKuE04qPD2X96A6kLHum371Mh71lLmr-WXyq_eQpX9qyfzJyUfGgwQPLzhwq_q1Qob7wqWrLaypgG4bmE"",
                ""alg"": ""RS256"",
                ""dq"": ""afjaNbiXqWsNc2Dpud77_SsQqBgFu0mYsYXCop3dSkQYWAYH290PghdK35luXVj68P0egchYxct5SbFiZekw4Yy2cZQVznl-Pk92qitAyC61wXvuhwutmbiOUoAJ2Hn2jXW10UJhBG6rZIQVejSFC-0J-hJcn7GZh0DCa8MtvY0"",
                ""n"": ""rne8LFusF3b_eO4GJtg02Xm_r8sjyMAGI_0P4WF-rSw1XAS5c8SZ91p0FR31aylI7KthZTdqOM3j9E6bOgqpVsYTafyGOlgAf87UnesNpXlIK9aKGcJ60fXFjsShG4Z0Rf5yZmdTdHRDcZl0J1xFOfYIxgZfebf_-Q64CqD8u35ANKg5Tp4PbW0tgjYNAB2XfHMKJJKPEqGPGXsMqk04R0UEjG0x6aNL68gkHxOLtiqBBWALLs7_u9wGR68CpvFElTV0QV-21FJ2O5Jl1UtgzzHaGOk7GEAvbc1UWXIqgO43Oa09HvjVS4R-LbOS0dL6lQnhtT0HyOh8sGAdOw29NQ""
            }";

            JsonWebKey jsonWebKey = new JsonWebKey(json);
            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            identityServerBuilder.AddSigningCredential(credentials);
        }

        [Fact]
        public void AddSigningCredential_with_json_web_key_containing_symmetric_key_should_throw_exception()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            String json =
            @"{
                ""alg"" : ""HS256"",
                ""kty"" : ""oct"",
                ""use"" : ""sig"",
                ""k"" : ""y5FHaQFtC294HLAtPXAcMkxZ5gHzCq24223vSYQUrDuu-3CUw7UzPru-AX30ubeB2IM_gUsNQ80bX22wwSk_3LC6XxYxqeGJZSeoQqHG0VNbaWCVkqeuB_HOiL1-ksPfGT-o8_A_Uv-6zi2NaEOYpnIyff5LpdW__LhiE-bhIenaw7GhoXSAfsGEZfNZpUUOU35NAiN2dv0T5vptb87wkL1I2zLhV0pdLvWsDWgQPINEa8bbCA_mseBYpB1eioZvt0TZbp6CL9tiEoiikYV_F3IutrJ2SOWYtDNFeQ3sbyYP7zTzh9a2eyaM8ca5_q3qosI92AbZ7WpEFLa9cZ_O7g""
            }";

            JsonWebKey jsonWebKey = new JsonWebKey(json);
            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            Assert.Throws<InvalidOperationException>(() => identityServerBuilder.AddSigningCredential(credentials));
        }

        [Fact]
        public void AddDeveloperSigningCredential_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            identityServerBuilder.AddDeveloperSigningCredential();

            //clean up... delete stored rsa key
            var filename = Path.Combine(Directory.GetCurrentDirectory(), "tempkey.rsa");

            if (File.Exists(filename))
                File.Delete(filename);
        }

        [Fact]
        public void AddDeveloperSigningCredential_should_succeed_when_called_multiple_times()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            try
            {
                identityServerBuilder.AddDeveloperSigningCredential();

                //calling a second time will try to load the saved rsa key from disk. An exception will be throw if the private key is not serialized properly.
                identityServerBuilder.AddDeveloperSigningCredential();
            }
            finally
            {
                //clean up... delete stored rsa key
                var filename = Path.Combine(Directory.GetCurrentDirectory(), "tempkey.rsa");

                if (File.Exists(filename))
                    File.Delete(filename);
            }
        }

        [Theory]
        [InlineData(Constants.CurveOids.P256, SecurityAlgorithms.EcdsaSha256)]
        [InlineData(Constants.CurveOids.P384, SecurityAlgorithms.EcdsaSha384)]
        [InlineData(Constants.CurveOids.P521, SecurityAlgorithms.EcdsaSha512)]
        public void AddSigningCredential_with_valid_curve_should_succeed(string curveOid, string alg)
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            var key = new ECDsaSecurityKey(ECDsa.Create(
                ECCurve.CreateFromOid(Oid.FromOidValue(curveOid, OidGroup.All))));

            identityServerBuilder.AddSigningCredential(key, alg);
        }

        [Theory]
        [InlineData(Constants.CurveOids.P256, SecurityAlgorithms.EcdsaSha512)]
        [InlineData(Constants.CurveOids.P384, SecurityAlgorithms.EcdsaSha512)]
        [InlineData(Constants.CurveOids.P521, SecurityAlgorithms.EcdsaSha256)]
        public void AddSigningCredential_with_invalid_curve_should_throw_exception(string curveOid, string alg)
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            var key = new ECDsaSecurityKey(ECDsa.Create(
                ECCurve.CreateFromOid(Oid.FromOidValue(curveOid, OidGroup.All))));

            Assert.Throws<InvalidOperationException>(() => identityServerBuilder.AddSigningCredential(key, alg));
        }



        [Theory]
        [InlineData(Constants.CurveOids.P256, SecurityAlgorithms.EcdsaSha256, JsonWebKeyECTypes.P256)]
        [InlineData(Constants.CurveOids.P384, SecurityAlgorithms.EcdsaSha384, JsonWebKeyECTypes.P384)]
        [InlineData(Constants.CurveOids.P521, SecurityAlgorithms.EcdsaSha512, JsonWebKeyECTypes.P521)]
        public void AddSigningCredential_with_invalid_crv_value_should_throw_exception(string curveOid, string alg, string crv)
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            var key = new ECDsaSecurityKey(ECDsa.Create(
                ECCurve.CreateFromOid(Oid.FromOidValue(curveOid, OidGroup.All))));
            var parameters = key.ECDsa.ExportParameters(true);

            var jsonWebKeyFromECDsa = new JsonWebKey()
            {
                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                Use = "sig",
                Kid = key.KeyId,
                KeyId = key.KeyId,
                X = Base64UrlEncoder.Encode(parameters.Q.X),
                Y = Base64UrlEncoder.Encode(parameters.Q.Y),
                D = Base64UrlEncoder.Encode(parameters.D),
                Crv = crv.Replace("-", string.Empty),
                Alg = SecurityAlgorithms.EcdsaSha256
            };
            Assert.Throws<InvalidOperationException>(() => identityServerBuilder.AddSigningCredential(jsonWebKeyFromECDsa, alg));
        }
    }
}
