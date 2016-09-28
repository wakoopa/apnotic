class ProviderToken

  ALGORITHM = "ES256".freeze

  def initialize(key, team_id, key_id)
    @key     = OpenSSL::PKey::EC.new(key)
    @team_id = team_id
    @key_id  = key_id
  end

  def token
    JWT.encode(payload, @key, ALGORITHM, header_fields)
  end

  private

  def payload
    {
      iss: @team_id,
      iat: Time.now.to_i
    }
  end

  def header_fields
    {
      alg: ALGORITHM,
      kid: @key_id
    }
  end

end