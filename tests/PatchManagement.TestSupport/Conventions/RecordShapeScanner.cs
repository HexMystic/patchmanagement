using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace PatchManagement.TestSupport.Conventions;

/// <summary>
/// Finds records whose members look secret-bearing, so a compiler-generated <c>ToString()</c> cannot
/// print a secret into a log (ADR 0012 decision C).
///
/// <para>An <b>enforcement aid, not a completeness proof.</b> It catches the mechanical mistake —
/// someone adds a <c>string Password</c> to a record and a caller logs the record — which is
/// precisely the mistake that is easy to make and invisible in review.</para>
/// </summary>
public static class RecordShapeScanner
{
    /// <summary>
    /// True for both record kinds.
    ///
    /// <para>The second clause is load-bearing and was added after a re-review found the first
    /// clause alone was silently incomplete: <c>&lt;Clone&gt;$</c> is emitted for record
    /// <b>classes</b> only, so every record <b>struct</b> was invisible to a scan that two documents
    /// claimed pinned it. Record structs are copied by value and get no clone method, but both kinds
    /// get a compiler-generated <c>PrintMembers(StringBuilder)</c>.</para>
    ///
    /// <para>The <c>IsValueType</c> guard keeps a hand-written <c>PrintMembers</c> on an ordinary
    /// class from being mistaken for a record. Non-record classes stay out of scope deliberately:
    /// they have no generated <c>ToString()</c>, so there is nothing to leak through.</para>
    /// </summary>
    public static bool IsRecord(Type type) =>
        type.GetMethod("<Clone>$", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic) is not null
        || (type.IsValueType
            && type.GetMethod(
                "PrintMembers",
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                types: [typeof(StringBuilder)],
                modifiers: null) is not null);

    /// <summary>
    /// Members whose name matches <paramref name="vocabulary"/> and whose type can actually carry a
    /// secret. The type filter matters: a member named <c>Credential</c> typed <c>CredentialRef</c>
    /// holds a Guid, not a secret, and flagging it would train people to ignore this test.
    /// Compiler-generated members (record backing fields) are excluded to avoid double-reporting.
    /// </summary>
    public static IEnumerable<MemberInfo> SecretishMembers(Type type, Regex vocabulary) =>
        type.GetMembers(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(m => m is PropertyInfo or FieldInfo)
            .Where(m => m.GetCustomAttribute<System.Runtime.CompilerServices.CompilerGeneratedAttribute>() is null)
            .Where(m => vocabulary.IsMatch(m.Name))
            .Where(m => MemberType(m) is { } t && (t == typeof(string) || t == typeof(byte[])));

    /// <summary>
    /// Every record in <paramref name="assemblies"/> with a secret-shaped member, minus
    /// <paramref name="covered"/> — types with a hand-written redacting <c>ToString()</c>, each of
    /// which a behavioural test should separately prove actually redacts.
    /// </summary>
    public static IReadOnlyList<Type> Uncovered(
        IEnumerable<Assembly> assemblies, Regex vocabulary, IEnumerable<Type> covered) =>
        assemblies
            .SelectMany(SafeGetTypes)
            .Where(IsRecord)
            .Where(t => SecretishMembers(t, vocabulary).Any())
            .Distinct()
            .Except(covered)
            .OrderBy(t => t.FullName, StringComparer.Ordinal)
            .ToList();

    /// <summary>Describes a type and the members that tripped the scan, by NAME only — never a value.</summary>
    public static string Describe(Type type, Regex vocabulary) =>
        $"{type.FullName} [{string.Join(", ", SecretishMembers(type, vocabulary).Select(m => m.Name))}]";

    private static Type? MemberType(MemberInfo member) => member switch
    {
        PropertyInfo p => p.PropertyType,
        FieldInfo f => f.FieldType,
        _ => null,
    };

    // A partially-loadable assembly still yields the types that did load; throwing here would turn a
    // missing optional dependency into a failure of every convention test in the suite.
    private static IEnumerable<Type> SafeGetTypes(Assembly assembly)
    {
        try { return assembly.GetTypes(); }
        catch (ReflectionTypeLoadException ex) { return ex.Types.OfType<Type>(); }
    }
}
