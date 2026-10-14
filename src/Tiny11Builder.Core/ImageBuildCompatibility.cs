namespace Tiny11Builder.Core;

internal static class ImageBuildCompatibility
{
    internal static int ServicingBase(int build) => build switch
    {
        22631 => 22621,
        26200 or 26300 => 26100,
        _ => build // Unknown Insider builds require an exact match.
    };
}
