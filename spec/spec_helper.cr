ENV["MARTEN_ENV"] = "test"

require "spec"
require "sqlite3"
require "../src/marten_signed_id"
require "marten/spec"

require "./test_project/app"
require "./test_project/models/**"

Marten.configure :test do |config|
  config.secret_key = "__insecure_spec_secret_#{Random::Secure.random_bytes(16).hexstring}__"
  config.log_level = ::Log::Severity::None

  config.installed_apps = [MartenSignedIdSpecApp]

  config.database do |db|
    db.backend = :sqlite
    db.name = ":memory:"
  end
end
