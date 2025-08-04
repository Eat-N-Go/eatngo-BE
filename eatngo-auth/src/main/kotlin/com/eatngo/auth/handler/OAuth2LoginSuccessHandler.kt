package com.eatngo.auth.handler

import com.eatngo.auth.constants.AuthenticationConstants.ACCESS_TOKEN
import com.eatngo.auth.constants.AuthenticationConstants.PRINCIPAL_KEY
import com.eatngo.auth.constants.AuthenticationConstants.SET_COOKIE_HEADER
import com.eatngo.auth.token.TokenProvider
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component

@Component
class OAuth2LoginSuccessHandler(
    private val tokenProvider: TokenProvider,
    private val postProcessor: OAuth2SuccessPostProcessor,
    @Value("\${oauth2.redirect.success-url:http://localhost:3000}")
    private val successRedirectUrl: String
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val attributes = (authentication.principal as OAuth2User).attributes
        val userId = attributes[PRINCIPAL_KEY]?.toString()?.toLongOrNull()
            ?: throw IllegalArgumentException("User ID not found")

        // 기존 토큰이 있다면 삭제
        request.cookies
            ?.find { cookie -> cookie.name == ACCESS_TOKEN }
            ?.value
            ?.let { tokenProvider.deleteRefreshToken(it) }

        val loginUser = postProcessor.postProcess(userId, response)
        val accessToken = tokenProvider.createAccessToken(loginUser)
        tokenProvider.createRefreshToken(loginUser)

        val responseCookie = tokenProvider.createHttpOnlyCookie(ACCESS_TOKEN, accessToken)
        response.addHeader(SET_COOKIE_HEADER, responseCookie.toString())
        response.contentType = "application/json"

        val locationHeader = "Location"
        if (response.getHeader(locationHeader) == null) {
            response.status = HttpServletResponse.SC_MOVED_TEMPORARILY
            response.setHeader(locationHeader, successRedirectUrl)
        }

    }
}