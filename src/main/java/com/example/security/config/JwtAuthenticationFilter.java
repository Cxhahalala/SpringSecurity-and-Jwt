package com.example.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
// 生成一个构造函数,初始化所有标注了 final 或 @NonNull 的字段。
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    //继承OncePerRequestFilter的方法

    /**
     *
     * @param request http请求
     * @param response 响应
     * @param filterChain 过滤器链
     */
    @Override
    protected void doFilterInternal(
         @NonNull HttpServletRequest request,
         @NonNull   HttpServletResponse response,
         @NonNull   FilterChain filterChain
    ) throws ServletException, IOException {
        // 该字段通常携带用户的认证信息
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        //如果不存在Authorization字段，则客户端请求没有携带认证信息
        //Bearer 是 JWT 的标准认证头格式，用于标识后续的内容是一个 Token。
        //如果不符合该格式，则说明请求头中没有合法的 JWT。
        //如果 authHeader 为空或格式不正确，直接调用过滤器链的 doFilter 方法，将请求传递给下一个过滤器。
        //返回结束当前过滤器的执行，不再处理当前请求的 Token 验证逻辑。
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail=jwtService.extractUsername(jwt);
        // 如果userEmail存在，并且未被认证，
        if(userEmail !=null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt,userDetails)){
                //使用UsernamePasswordAuthenticationToken对象更新安全上下文
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //更新SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
