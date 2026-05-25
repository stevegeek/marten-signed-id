ENV["MARTEN_ENV"] = "test"

require "spec"
require "sqlite3"
require "../src/marten_signed_id"
require "marten/spec"

require "./test_project/app"
require "./test_project/models/**"

# Fixed test secret — reproducible failure modes beat per-run randomness
# when something breaks. The leading/trailing markers make accidental
# reuse outside the suite obvious in greps. Must stay ≥ 32 bytes to
# satisfy `MartenSignedId.validate_secret_key!`.
SPEC_SECRET_KEY = "__insecure_spec_secret_DO_NOT_USE__"

Marten.configure :test do |config|
  config.secret_key = SPEC_SECRET_KEY
  config.log_level = ::Log::Severity::None

  config.installed_apps = [MartenSignedIdSpecApp]

  config.database do |db|
    db.backend = :sqlite
    db.name = ":memory:"
  end
end
