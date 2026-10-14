using System.Runtime.Versioning;
using System.Text.Json;
using Tiny11Builder.App;
using Tiny11Builder.Core;
using Xunit;

namespace Tiny11Builder.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class ConfigurationTests
{
    [Fact]
    public void Old_recipes_preserve_defaults_and_configuration_round_trips()
    {
        var old = JsonSerializer.Deserialize<BuildRecipe>("""{"SchemaVersion":1,"SelectedOptions":[]}""", JsonDefaults.Options)!;
        old.ValidateOptions();
        Assert.Empty(old.ConfigurationOptions);
        using var fixture = new BuildFixture();
        var path = Path.Combine(fixture.Root, "configuration.json");
        var recipe = old with { ConfigurationOptions = ["mouse", "classic-menu", "auto-updates"] };
        recipe.Write(path);
        Assert.Equal(recipe.ConfigurationOptions, BuildRecipe.Read(path).ConfigurationOptions);
    }

    [Theory]
    [InlineData("unknown", "mouse")]
    [InlineData("mouse", "mouse")]
    public void Invalid_configuration_is_rejected(string first, string second) =>
        Assert.Throws<InvalidDataException>(() => new BuildRecipe { ConfigurationOptions = [first, second] }.ValidateOptions());

    [Fact]
    public void Security_and_update_disabling_are_not_in_suggested_preferences()
    {
        Assert.All(ConfigurationCatalog.Options.Select(option => new ConfigurationChoice(option)), choice => Assert.False(choice.Selected));
        foreach (var id in new[] { "core-isolation", "auto-updates", "fth", "mouse", "mmcss" })
            Assert.False(ConfigurationCatalog.Options.Single(option => option.Id == id).Recommended);
    }

    [Fact]
    public async Task Changing_configuration_on_resume_is_refused_before_mutation()
    {
        using var fixture = new BuildFixture();
        var failed = await JobScenarios.InterruptAtCommitAsync(fixture);
        var before = JobScenarios.Snapshot(failed.WorkDirectory);
        var recipe = JobScenarios.OriginalRecipe(failed.WorkDirectory) with { ConfigurationOptions = ["mouse"] };
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Engine.ResumeAsync(JobScenarios.JobFile(failed), recipe, null, CancellationToken.None));
        Assert.Equal(before, JobScenarios.Snapshot(failed.WorkDirectory));
    }
}
