# EthernetIPSharp — the INDEPENDENT browse (0x55) conformance peer for the poll live tests
# (DESIGN §11.7). EthernetIPSharp (github.com/CristianMori/EthernetIpSharp, C#, MIT) is a third, fully
# independent EtherNet/IP implementation. Its LogixDispatcher/SymbolObject serves Read/Write Named Tag
# (0x4C/0x4D) AND — unlike cpppo and libplctag's ab_server — the Logix tag-LIST service
# Get_Instance_Attribute_List (0x55) on the Symbol class (0x6B). It is therefore the peer that CLOSES
# the sb/browse gap with a real, non-ours 0x55 implementation: the first genuine wire validation of
# `enip::list_tags` (previously exercised only against `duplex` fixtures — cpppo and ab_server both
# refuse 0x55).
#
# The build overwrites the repo's tests/LogixHost/Program.cs (reusing that project's references to the
# dependency-free EthernetIPSharp.Logix/.Protocol/.Cip libraries) with test-infra/ethernetip-sharp/
# Program.cs, which binds 0.0.0.0 and serves the §11.1 bottling-line tag layout.
#
# Build + run standalone:
#   docker build -t ethernetip-sharp-sim test-infra/ethernetip-sharp
#   docker run --rm -p 44821:44818 ethernetip-sharp-sim   # host :44821 to coexist with the others
#
# It is a bare TCP/CIP target (no UDP class-1), so ordinary port publishing works on any docker host.

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
RUN git clone --depth 1 https://github.com/CristianMori/EthernetIpSharp.git /src
# Bind 0.0.0.0 + the §11.1 tag set. Overwrites the loopback-only sample host with ours.
COPY Program.cs /src/tests/LogixHost/Program.cs
WORKDIR /src
RUN dotnet publish tests/LogixHost/LogixHost.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/runtime:8.0
COPY --from=build /app /app
EXPOSE 44818/tcp
ENTRYPOINT ["dotnet", "/app/LogixHost.dll"]
