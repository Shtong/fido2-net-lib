﻿using System;
using System.Collections.Generic;
using System.Text;
using Fido2NetLib.Objects;
using Newtonsoft.Json;
using Shouldly;
using Xunit;

namespace Fido2.Tests.Models.Objects
{
    public class AuthenticatorTransportTests
    {
        [Fact]
        public void IsSerializable()
        {
            var list = new[]
{
                AuthenticatorTransport.Ble,
                AuthenticatorTransport.Usb,
                AuthenticatorTransport.Nfc,
                AuthenticatorTransport.Lightning,
                AuthenticatorTransport.Internal
            };

            var serialized = JsonConvert.SerializeObject(list);
            var deserialized = JsonConvert.DeserializeObject<AuthenticatorTransport[]>(serialized);

            deserialized.ShouldBe(list);
        }
    }
}