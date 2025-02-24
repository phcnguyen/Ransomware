namespace Ransomware.Injector;

/// <summary>
/// Defines the available methods for injecting code into a target process.
/// </summary>
public enum InjectionMethod
{
    /// <summary>
    /// Creates a new remote thread in the target process to execute the injected payload.
    /// </summary>
    CreateRemoteThread,

    /// <summary>
    /// Queues an Asynchronous Procedure Call (APC) in a suspended thread of the target process.
    /// The payload executes when the thread resumes execution.
    /// </summary>
    QueueUserAPC
}