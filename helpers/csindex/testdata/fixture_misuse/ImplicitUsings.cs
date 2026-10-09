// A file of a project with ImplicitUsings: there is no `using System;`, and
// csindex does not load the project, so `Exception` binds to nothing here.

using Microsoft.Extensions.Logging;

namespace MisuseFixture
{
    public class ImplicitUsings
    {
        private readonly ILogger _log;

        public ImplicitUsings(ILogger log)
        {
            _log = log;
        }

        /// The root type by its written name: the low-confidence tier.
        public void CatchesUnresolvedRoot()
        {
            try
            {
                _log.LogError(null, "work");
            }
            catch (Exception err)
            {
                _log.LogError(err, "unresolved");
            }
        }

        /// Another name that binds to nothing is not the root type.
        public void CatchesUnresolvedNarrow()
        {
            try
            {
                _log.LogError(null, "work");
            }
            catch (TimeoutException err)
            {
                _log.LogError(err, "narrow");
            }
        }
    }
}
