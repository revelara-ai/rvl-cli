// Misuse-shape fixture: one function per identity of the misuse lane, and one
// per form that must stay out of it. The logger is a stub in this file, so the
// receiver resolves without a package restore.

using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Microsoft.Extensions.Logging
{
    public interface ILogger
    {
        void LogError(Exception err, string message);
    }
}

namespace MisuseFixture
{
    public class Holder
    {
        public int Result { get; set; }
        public void Wait() { }
    }

    public class Shapes
    {
        private readonly ILogger _log;

        public Shapes(ILogger log)
        {
            _log = log;
        }

        private static void Work() { }
        private static Task<int> Fetch() => Task.FromResult(1);

        // -- overbroad_catch --------------------------------------------------

        /// Two handlers for the root type, one written with its namespace:
        /// one packet, count 2.
        public void CatchesRoot()
        {
            try
            {
                Work();
            }
            catch (Exception err)
            {
                _log.LogError(err, "first");
            }
            try
            {
                Work();
            }
            catch (System.Exception err)
            {
                _log.LogError(err, "second");
            }
        }

        public void CatchesBare()
        {
            try
            {
                Work();
            }
            catch
            {
                _log.LogError(null, "bare");
            }
        }

        /// Bounded: the handler names a narrower type.
        public void CatchesNarrow()
        {
            try
            {
                Work();
            }
            catch (IOException err)
            {
                _log.LogError(err, "narrow");
            }
        }

        /// Bounded: the filter narrows the root type.
        public void CatchesFiltered()
        {
            try
            {
                Work();
            }
            catch (Exception err) when (err is IOException)
            {
                _log.LogError(err, "filtered");
            }
        }

        /// The error propagates.
        public void CatchesAndRethrows()
        {
            try
            {
                Work();
            }
            catch (Exception err)
            {
                _log.LogError(err, "rethrown");
                throw;
            }
        }

        /// The emission lane's catch_clause swallow. One handler, one report.
        public void Swallows()
        {
            try
            {
                Work();
            }
            catch (Exception)
            {
            }
        }

        // -- sync_over_async --------------------------------------------------

        public int WaitsOnResult(Task<int> task)
        {
            return task.Result + Fetch().Result;
        }

        public void WaitsOnWait(Task task)
        {
            task.Wait();
        }

        public int WaitsOnGetResult(Task<int> task)
        {
            var first = task.GetAwaiter().GetResult();
            return first + task.ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public int WaitsOnValueTask(ValueTask<int> pending)
        {
            return pending.Result;
        }

        /// Bounded: the function awaits.
        public async Task<int> Awaits(Task<int> task)
        {
            return await task;
        }

        /// Bounded: the wait has a timeout.
        public bool WaitsWithTimeout(Task task)
        {
            return task.Wait(TimeSpan.FromSeconds(5));
        }

        /// The same member names on a type that is not a task.
        public int ReadsAHolder(Holder holder)
        {
            holder.Wait();
            return holder.Result;
        }
    }
}
