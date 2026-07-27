using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors;

/// <summary>
/// Resolves the right <see cref="IEndpointConnector"/> for a target's protocol. Callers depend on
/// this, not on a concrete connector, so protocol selection stays a lookup — never a branch in
/// business code.
/// </summary>
public interface IEndpointConnectorRegistry
{
    IEndpointConnector For(EndpointProtocol protocol);
    IEndpointConnector For(EndpointTarget target);
}

internal sealed class EndpointConnectorRegistry : IEndpointConnectorRegistry
{
    private readonly IReadOnlyDictionary<EndpointProtocol, IEndpointConnector> _byProtocol;

    public EndpointConnectorRegistry(IEnumerable<IEndpointConnector> connectors)
    {
        var map = new Dictionary<EndpointProtocol, IEndpointConnector>();
        foreach (var connector in connectors)
            map[connector.Protocol] = connector;
        _byProtocol = map;
    }

    public IEndpointConnector For(EndpointProtocol protocol) =>
        _byProtocol.TryGetValue(protocol, out var connector)
            ? connector
            : throw new NotSupportedException($"No connector is registered for protocol '{protocol}'.");

    public IEndpointConnector For(EndpointTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return For(target.Protocol);
    }
}
