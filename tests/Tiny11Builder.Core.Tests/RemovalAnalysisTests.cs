using Tiny11Builder.Core;
using Xunit;

namespace Tiny11Builder.Core.Tests;

public sealed class RemovalAnalysisTests
{
    [Theory]
    [InlineData("<!DOCTYPE html><html><body>report</body></html>", "HTML")]
    [InlineData("\uFEFF \n<html>report</html>", "HTML")]
    [InlineData("```json\n{}\n```", "Markdown")]
    [InlineData("{ broken", "JSON")]
    [InlineData("null", "为空")]
    [InlineData("{\"SchemaVersion\":1,\"ReportType\":\"Tiny11Builder.AdvancedRemovalInventory\"}", "原始组件清单")]
    [InlineData("{}", "不是支持的分析格式")]
    public void Wrong_file_contents_produce_actionable_errors(string text, string expected)
    {
        Assert.Contains(expected, Assert.Throws<InvalidDataException>(() => RemovalAnalysis.Parse(text)).Message);
    }

    [Fact]
    public void Template_preserves_identity_and_state_and_requires_completion()
    {
        var template = RemovalAnalysis.CreateTemplate(Image, [Item]);
        Assert.Equal(Image, template.Image);
        var entry = Assert.Single(template.Components);
        Assert.Equal(Item.Identity, entry.Identity);
        Assert.Equal(Item.Detail, entry.OriginalDetail);
        Assert.Equal(Item.Protected, entry.Protected);
        Assert.Equal(RemovalRecommendation.Review, entry.Recommendation);
        var json = System.Text.Json.JsonSerializer.Serialize(template, JsonDefaults.Options);
        Assert.Contains("模板", Assert.Throws<InvalidDataException>(() => RemovalAnalysis.Parse(json)).Message);
        Assert.Throws<InvalidDataException>(() => template.Match(Image, [Item]));
        var completed = template with { IsTemplate = false, Components = [entry with { Recommendation = RemovalRecommendation.Disable }] };
        var read = RemovalAnalysis.Parse(System.Text.Json.JsonSerializer.Serialize(completed, JsonDefaults.Options));
        Assert.Equal(RemovalRecommendation.Disable, read.Match(Image, [Item])[Item.Key].Recommendation);
    }
    private static readonly WindowsImage Image = new(4, "Windows 11", "", "x64", new Version(10, 0, 22621, 4169), "Professional", "Client", 1);
    private static readonly ImageInventoryItem Item = new(ImageItemKind.Service, "DiagTrack", "Start=2; type=16; telemetry", true);
    private static RemovalAnalysis Report(params RemovalAnalysisEntry[] entries) => new()
    {
        SchemaVersion = 1, ReportType = "Tiny11Builder.RemovalAnalysis", Image = Image, Components = entries
    };
    private static RemovalAnalysisEntry Entry(RemovalRecommendation action = RemovalRecommendation.Disable) => new()
    { Kind = Item.Kind, Identity = Item.Identity, Recommendation = action };

    [Fact]
    public void Exact_match_returns_recommendations_without_modifying_inventory()
    {
        var matched = Report(Entry()).Match(Image, [Item]);
        Assert.Equal(RemovalRecommendation.Disable, matched[Item.Key].Recommendation);
        Assert.Equal("Start=2; type=16; telemetry", Item.Detail);
    }

    [Fact]
    public void Wrong_image_duplicate_or_unknown_identity_rejects_whole_report()
    {
        Assert.Throws<InvalidDataException>(() => Report(Entry()).Match(Image with { Version = new Version(10, 0, 26100, 1) }, [Item]));
        Assert.Throws<InvalidDataException>(() => Report(Entry(), Entry()).Match(Image, [Item]));
        Assert.Throws<InvalidDataException>(() => Report(Entry() with { Identity = "diagtrack" }).Match(Image, [Item]));
        Assert.Throws<InvalidDataException>(() => Report(Entry() with { Kind = ImageItemKind.Feature }).Match(Image, [Item]));
    }

    [Fact]
    public void Unsupported_disable_and_absent_removals_are_rejected()
    {
        var capability = new ImageInventoryItem(ImageItemKind.Capability, "Test~~~~0.0.1.0", "Not Present", true);
        var entry = new RemovalAnalysisEntry { Kind = capability.Kind, Identity = capability.Identity, Recommendation = RemovalRecommendation.Remove };
        Assert.Throws<InvalidDataException>(() => Report(entry).Match(Image, [capability]));
        Assert.Throws<InvalidDataException>(() => Report(entry with { Recommendation = RemovalRecommendation.Disable }).Match(Image, [capability]));
        Assert.Single(Report(entry with { Recommendation = RemovalRecommendation.Keep }).Match(Image, [capability]));
    }

    [Theory]
    [InlineData(RemovalRecommendation.Keep)]
    [InlineData(RemovalRecommendation.Review)]
    public void Non_action_recommendations_are_preserved(RemovalRecommendation action)
    {
        Assert.Equal(action, Report(Entry(action)).Match(Image, [Item])[Item.Key].Recommendation);
    }
}
