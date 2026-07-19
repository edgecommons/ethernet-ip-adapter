// EthernetIPSharp Logix server host — the INDEPENDENT browse (0x55) conformance peer for the poll
// live tests (DESIGN §11.7). Overwrites the repo's tests/LogixHost/Program.cs (reusing that project's
// references to EthernetIPSharp.Logix/.Protocol/.Cip) with a host that binds 0.0.0.0 (so it is
// reachable from outside the container) and serves the bottling-line tag layout (§11.1) that
// live_ethernetipsharp.rs drives.
//
// EthernetIPSharp (github.com/CristianMori/EthernetIpSharp, C#) is a third, fully independent
// EtherNet/IP implementation — its LogixDispatcher/SymbolObject serves Read/Write Named Tag AND, unlike
// cpppo and ab_server, the Logix tag-LIST service Get Instance Attribute List (0x55) on the Symbol
// class (0x6B). It is therefore the peer that CLOSES the sb/browse gap with a real, non-ours 0x55
// implementation (the first genuine wire validation of enip::list_tags).

using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;
using EthernetIPSharp.Protocol;

var identity = new IdentityInfo
{
    VendorId = 0x1337,
    DeviceType = 0x0E,          // Communications Adapter
    ProductCode = 55,
    MajorRevision = 32,
    MinorRevision = 11,
    SerialNumber = 0x0ED6_C055,
    ProductName = "EthernetIPSharp Logix (edgecommons enip conformance peer)",
};

var logix = new LogixDispatcher(new TagDatabase(), identity);

// The §11.1 bottling-line tag layout. Scalars seed deterministic values so the live test asserts EXACT
// decoded values; the array + writable setpoint exercise the array and write/read-back paths; the set
// as a whole is what browse (0x55) must enumerate.
logix.Tags.AddTag("LINE_SPEED", LogixDataTypes.REAL).Write<float>(0, 123.5f);
logix.Tags.AddTag("FILL_TEMP", LogixDataTypes.REAL).Write<float>(0, 20.0f);
logix.Tags.AddTag("TANK_LEVEL", LogixDataTypes.REAL).Write<float>(0, 42.0f);
logix.Tags.AddTag("PRODUCT_COUNT", LogixDataTypes.DINT).Write<int>(0, 4242);
logix.Tags.AddTag("FILL_SETPOINT", LogixDataTypes.REAL).Write<float>(0, 0.0f);
logix.Tags.AddTag("MOTOR_RUN", LogixDataTypes.DINT).Write<int>(0, 1);

// REAL[8] array — read as a JSON array of 8 by the adapter; a browse entry with array dims (so
// enip marks it value-unsupported, the same class as cpppo's SSTRING RECIPE).
var zone = logix.Tags.AddTag("ZONE_TEMPS", LogixDataTypes.REAL, elementCount: 8);
for (int i = 0; i < 8; i++)
    zone.Write<float>(i * 4, 10.0f + i);

var adapter = new EipAdapter(logix, identity);
await adapter.ListenAsync(IPAddress.Any, 44818);

Console.WriteLine("EthernetIPSharp Logix server listening on 0.0.0.0:44818");
Console.WriteLine("Tags: LINE_SPEED(REAL)=123.5, FILL_TEMP(REAL), TANK_LEVEL(REAL), PRODUCT_COUNT(DINT)=4242,");
Console.WriteLine("      FILL_SETPOINT(REAL, writable), MOTOR_RUN(DINT)=1, ZONE_TEMPS(REAL[8])=[10..17]");
Console.WriteLine("Serves Read/Write Named Tag (0x4C/0x4D) + Get_Instance_Attribute_List (0x55) browse.");

await Task.Delay(Timeout.Infinite, new CancellationTokenSource().Token);
