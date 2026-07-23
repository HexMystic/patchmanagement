using PatchManagement.Contracts.States;
using Xunit;

namespace PatchManagement.Contracts.Tests;

public class EndpointStateNamesTests
{
    [Fact]
    public void Every_state_round_trips_through_its_db_name()
    {
        foreach (var state in Enum.GetValues<EndpointState>())
        {
            var name = state.ToDbValue();
            Assert.Equal(state, EndpointStateNames.FromDbValue(name));
        }
    }

    [Theory]
    [InlineData(EndpointState.AuthFailed, "auth-failed")]
    [InlineData(EndpointState.AssessedMissing, "assessed-missing")]
    [InlineData(EndpointState.RollbackInProgress, "rollback-in-progress")]
    [InlineData(EndpointState.RolledBack, "rolled-back")]
    public void Names_are_stable_kebab_case(EndpointState state, string expected)
    {
        Assert.Equal(expected, state.ToDbValue());
    }

    [Fact]
    public void Unknown_db_value_throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => EndpointStateNames.FromDbValue("not-a-state"));
    }
}
