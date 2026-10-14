using System.Runtime.Versioning;
using Tiny11Builder.Core;
using Xunit;

namespace Tiny11Builder.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class ImageIdentityTests
{
    private static WindowsImage Image(int build) => new(1, "Windows 11 Pro", "", "x64",
        new(10, 0, build, 4169), "Professional", "Client", 1);

    [Theory]
    [InlineData(22621, 22631)]
    [InlineData(26100, 26200)]
    [InlineData(26100, 26300)]
    [InlineData(26200, 26300)]
    [InlineData(29683, 29683)]
    public void Known_forward_enablement_transitions_are_accepted(int original, int committed) =>
        BuildEngine.RequireSameImage([Image(committed)], Image(original), "Final image");

    [Theory]
    [InlineData(22631, 22621)]
    [InlineData(22631, 26100)]
    [InlineData(26100, 26301)]
    [InlineData(29683, 29684)]
    public void Downgrades_different_families_and_unknown_transitions_are_rejected(int original, int committed)
    {
        var error = Assert.Throws<InvalidDataException>(() => BuildEngine.RequireSameImage([Image(committed)], Image(original), "Final image"));
        Assert.Contains("Expected:", error.Message);
        Assert.Contains("Actual:", error.Message);
    }

    [Fact]
    public void Enablement_transition_does_not_allow_wrong_edition_architecture_name_or_installation()
    {
        var expected = Image(22621);
        var actual = Image(22631);
        foreach (var wrong in new[] { actual with { Edition = "Core" }, actual with { Architecture = "arm64" },
                     actual with { Name = "Windows 11 Home" }, actual with { Installation = "Server" }, actual with { Version = new(11, 0, 22631) } })
            Assert.Throws<InvalidDataException>(() => BuildEngine.RequireSameImage([wrong], expected, "Final image"));
        Assert.Throws<InvalidDataException>(() => BuildEngine.RequireSameImage([actual, actual], expected, "Final image"));
    }
}
