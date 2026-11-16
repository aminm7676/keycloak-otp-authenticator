<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('otp'); section>
    <#if section = "header">
        Enter verification code
    <#elseif section = "form">
        <form id="kc-otp-login-form"
              class="${properties.kcFormClass!}"
              action="${url.loginAction}"
              method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label for="otp" class="${properties.kcLabelClass!}">Verification code</label>
                <input id="otp"
                       name="otp"
                       type="text"
                       inputmode="numeric"
                       pattern="[0-9]{6}"
                       minlength="6"
                       maxlength="6"
                       autocomplete="one-time-code"
                       autofocus
                       class="${properties.kcInputClass!}"
                       aria-invalid="<#if messagesPerField.existsError('otp')>true<#else>false</#if>"
                       aria-describedby="otp-help <#if messagesPerField.existsError('otp')>input-error-otp</#if>" />
                <div id="otp-help" class="${properties.kcInputHelperTextClass!}">
                    Enter the six-digit code. It expires in ${otpExpiresInMinutes} minutes.
                </div>
                <#if messagesPerField.existsError('otp')>
                    <span id="input-error-otp"
                          class="${properties.kcInputErrorMessageClass!}"
                          aria-live="polite">
                        ${kcSanitize(messagesPerField.get('otp'))?no_esc}
                    </span>
                </#if>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           name="login"
                           id="kc-login"
                           type="submit"
                           value="Verify" />
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
