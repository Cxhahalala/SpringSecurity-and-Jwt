package com.example.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    // 密钥
    private static final String SECRET_KEY = "5v8PsJz6G+Jk69fxWkMsXtbGyO1HTK+7OdjwNWUeeHE="; // 确保这是Base64字符串

    // 获取用户名
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // 提取主题作为用户名
    }

    // 获取过期时间
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // 获取单个的Claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 提取Claims(有效荷载)
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder() // 构建解析器
                .setSigningKey(getSignKey()) // 设置签名密钥
                .build() // 构建解析器对象
                .parseClaimsJws(token) // 解析JWT，验证签名，并提取Claims
                .getBody(); // 提取Claims 对象(有效荷载)
    }

    // 获取签名密钥
    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // Base64解码
        return Keys.hmacShaKeyFor(keyBytes); // 生成HS256签名密钥
    }

    // 生成JWT
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        System.out.println("Generating token for user: " + userDetails.getUsername());
        return Jwts
                .builder()
                .setClaims(extraClaims) // 设置额外声明
                .setSubject(userDetails.getUsername()) // 设置主题（用户名）
                .setIssuedAt(new Date(System.currentTimeMillis())) // Token 生效时间
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // Token 失效时间
                .signWith(getSignKey(), SignatureAlgorithm.HS256) // 签名，加密
                .compact();
    }

    // 生成不包含额外声明的JWT
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // 判断Token是否合法
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token); // 使用equals比较字符串
    }

    // 判断Token是否过期
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}

