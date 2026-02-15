# frozen_string_literal: true

module Verikloak
  module BFF
    # Shared constants for the BFF middleware layer.
    # Centralised here so that every module (HeaderGuard, JwtUtils,
    # ConsistencyChecks, etc.) references the same values.
    module Constants
      # Maximum JWT byte size accepted for unverified decoding.
      # Tokens exceeding this limit are treated as opaque (no claim inspection).
      MAX_TOKEN_BYTES = 8192

      # Regex matching Unicode control characters, used by log sanitisation.
      LOG_CONTROL_CHARS = /[[:cntrl:]]/

      # Maximum length for individual log field values to prevent log flooding
      # from oversized or malicious JWT claims.
      MAX_LOG_FIELD_LENGTH = 256
    end
  end
end
