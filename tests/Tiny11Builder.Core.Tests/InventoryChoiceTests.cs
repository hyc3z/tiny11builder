using Tiny11Builder.App;
using Tiny11Builder.Core;
using Xunit;

namespace Tiny11Builder.Core.Tests;

public sealed class InventoryChoiceTests
{
    [Fact]
    public void Importing_remove_or_disable_immediately_selects_the_recommended_action()
    {
        var service = new InventoryChoice(new(ImageItemKind.Service, "DiagTrack", "telemetry", false));

        service.ImportAnalysis(Entry(RemovalRecommendation.Remove));
        Assert.True(service.Selected);
        Assert.Equal(1, service.ModeIndex);
        Assert.Equal(ExpertActionMode.Remove, service.Action.Mode);

        service.Selected = false;
        service.ImportAnalysis(Entry(RemovalRecommendation.Disable));
        Assert.True(service.Selected);
        Assert.Equal(0, service.ModeIndex);
        Assert.Equal(ExpertActionMode.Disable, service.Action.Mode);
    }

    [Theory]
    [InlineData(RemovalRecommendation.Keep)]
    [InlineData(RemovalRecommendation.Review)]
    public void Importing_non_action_recommendations_preserves_manual_selection(RemovalRecommendation recommendation)
    {
        var choice = new InventoryChoice(new(ImageItemKind.Service, "DiagTrack", "telemetry", false))
        {
            Selected = true,
            ModeIndex = 1
        };

        choice.ImportAnalysis(Entry(recommendation));

        Assert.True(choice.Selected);
        Assert.Equal(1, choice.ModeIndex);
        Assert.Equal(recommendation, choice.Analysis?.Recommendation);
    }

    [Fact]
    public void Missing_analysis_entry_does_not_clear_manual_selection()
    {
        var choice = new InventoryChoice(new(ImageItemKind.Service, "DiagTrack", "telemetry", false))
        {
            Selected = true,
            ModeIndex = 1
        };

        choice.ImportAnalysis(null);

        Assert.True(choice.Selected);
        Assert.Equal(1, choice.ModeIndex);
    }

    private static RemovalAnalysisEntry Entry(RemovalRecommendation recommendation) => new()
    {
        Kind = ImageItemKind.Service,
        Identity = "DiagTrack",
        Recommendation = recommendation
    };
}
