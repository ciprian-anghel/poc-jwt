package com.mizu.pocjwt.services;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mizu.pocjwt.user.User;

@Service
public class JwtService {
	
	@Value("${security.jwt.token.secret-key:secret-key}")
	private String secretKey;
	
	public String generateToken(User userDetails) {
		return generateToken(userDetails, new HashMap<String, Object>());
	}
	
	public String generateToken(User userDetails, Map<String, Object> extraClaims) {
		Date now = new Date();
		Date validity = new Date(now.getTime() + 1000 * 60 * 24); // 24 hours
		Builder builder = JWT.create()
				  .withIssuer(userDetails.getEmail())
				  .withIssuedAt(now)
				  .withExpiresAt(validity)
				  .withClaim(JwtClaimType.FIRST_NAME.getClaim(), userDetails.getFirstName())
				  .withClaim(JwtClaimType.LAST_NAME.getClaim(), userDetails.getLastName())
				  .withClaim(JwtClaimType.EMAIL.getClaim(), userDetails.getEmail());
		addExtraClaims(builder, extraClaims);
		return builder.sign(Algorithm.HMAC256(secretKey));
	}
	
	public String extractStringClaim(JwtClaimType claim, String token) {
		Claim result = extractAllClaims(token).get(claim.getClaim());
		if (result == null) {
			throw new IllegalArgumentException("Claim was not found: " + claim);
		}
		return result.asString();
	}
	
	public Date extractDateClaim(JwtClaimType claim, String token) {
		Claim result = extractAllClaims(token).get(claim.getClaim());
		if (result == null) {
			throw new IllegalArgumentException("Claim was not found: " + claim);
		}
		return result.asDate();
	}
	
	public boolean isTokenValid(String token, UserDetails userDetails) {
		String userEmail = extractStringClaim(JwtClaimType.EMAIL, token);
		return userEmail.equals(userDetails.getUsername()) && !isTokenExpired(token);
	}
	
	private boolean isTokenExpired(String token) {
		return extractDateClaim(JwtClaimType.EXPIRATION_DATE, token).before(new Date());
	}
	
	private Builder addExtraClaims(Builder builder, Map<String, Object> extraClaims) {
		extraClaims.forEach((k, v) -> {
			if (String.class.isAssignableFrom(v.getClass())) {
				builder.withClaim(k, (String) v);
			} else if (Date.class.isAssignableFrom(v.getClass())) {
				builder.withClaim(k, (Date) v);
			} else if (Integer.class.isAssignableFrom(v.getClass())) {
				builder.withClaim(k, (Integer) v);
			} else if (Double.class.isAssignableFrom(v.getClass())) {
				builder.withClaim(k, (Double) v);
			} else {
				throw new IllegalArgumentException("Claim type is not supported: " + v.getClass());
			}
		});
		return builder;
	}
	
	private Map<String, Claim> extractAllClaims(String token) {
		Algorithm algorithm = Algorithm.HMAC256(secretKey);
		JWTVerifier verifier = JWT.require(algorithm).build();
		
		DecodedJWT decoded = verifier.verify(token);
		return decoded.getClaims();
	}
	
	public enum JwtClaimType {
		FIRST_NAME("firstName"),
		LAST_NAME("lastName"),
		EMAIL("email"),
		EXPIRATION_DATE("exp");
		
		private final String claim;
		
		private JwtClaimType(String claim) {
			this.claim = claim;
		}
		
		public String getClaim() {
			return this.claim;
		}
	}
}
