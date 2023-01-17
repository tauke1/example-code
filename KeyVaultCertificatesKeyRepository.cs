using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using NDA.Identity.Management.DataProtection.Exceptions;
using NDA.Identity.Management.KeyVault;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NDA.Identity.Management.DataProtection.Repositories
{
    public class KeyVaultCertificatesKeyRepository : IKeyVaultCertificatesKeyRepository
    {
        private readonly IKeyVaultService _keyVaultService;
        private readonly ILogger<KeyVaultCertificatesKeyRepository> _logger;
        private readonly IList<IAuthenticatedEncryptorFactory> _authenticatedEncryptorFactories;

        private const int SecretNameSegmentId = 2;

        public KeyVaultCertificatesKeyRepository(IKeyVaultService keyVaultService,
            ILogger<KeyVaultCertificatesKeyRepository> logger, IOptions<KeyManagementOptions> keyManagementOptions)
        {
            _keyVaultService = keyVaultService ?? throw new ArgumentNullException(nameof(keyVaultService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            
            if(keyManagementOptions == null) 
            {
                throw new ArgumentNullException(nameof(keyManagementOptions));
            }
            
            if(keyManagementOptions.Value == null) 
            {
                throw new ArgumentException($"Property {nameof(keyManagementOptions.Value)} must not be null, null value found", nameof(keyManagementOptions));
            }
            
            if(keyManagementOptions.Value.AuthenticatedEncryptorFactories == null) 
            {
                throw new ArgumentException($"Property {nameof(keyManagementOptions.Value)}.{nameof(keyManagementOptions.Value.AuthenticatedEncryptorFactories)}" +
                    $" must not be null, null value found", nameof(keyManagementOptions));
            }
            
            _authenticatedEncryptorFactories = keyManagementOptions.Value.AuthenticatedEncryptorFactories;
        }

        public async Task<DataProtectionKey> GetDataProtectionKeyAsync(string certName)
        {
            if(certName == null) 
            {
                throw new ArgumentNullException(nameof(certName));
            }
            
            if(certName.Trim() == string.Empty) 
            {
                throw new ArgumentException($"Argument must not be an empty string, empty string value found", nameof(certName));
            }
            
            _logger.LogInformation("DataProtection: Trying to make master key from certificate {certName} ", certName);

            CertificateDescriptor certificateDescriptor;

            try
            {
                var cert = await _keyVaultService.GetCertificateAsync(certName);
                
                var validationErrors = ValidateCertificate(cert);
                if (validationErrors.Count > 0)
                {
                    var message = $"DataProtection: certificate {certName} did not pass validation";
                    message += Environment.NewLine + string.Join(Environment.NewLine, validationErrors);
                    throw new KeyVaultCertificateNotValidException(message);
                }
                
                // Azure guarantees that they always return valid SecretId
                string secretName = cert.SecretId.Segments[SecretNameSegmentId];
                KeyVaultSecret certSecret = await _keyVaultService.GetSecretAsync(secretName);
                string certSecretValue = certSecret.Value;

                certificateDescriptor = ConvertToCertificateDescriptor(cert, certSecretValue);
            }
            catch (Exception ex)
            {
                string errorLogMessage =
                    "DataProtection: Cannot obtain required data for {certName} certificate or it's not valid";
                _logger.LogError(ex, errorLogMessage, certName);
                throw;
            }

            try
            {
                var encryptorDescriptor = BuildEncryptorDescriptor(certificateDescriptor.Secret);
                var key = new DataProtectionKey(certificateDescriptor.Version, certificateDescriptor.CreationDate,
                    certificateDescriptor.ActivationDate, certificateDescriptor.ExpirationDate, encryptorDescriptor,
                    _authenticatedEncryptorFactories);

                string successLogMessage =
                    "DataProtection: Certificate {certName} successfully converted to master key with id {keyId}";
                _logger.LogInformation(successLogMessage, certificateDescriptor.Name, key.KeyId);

                return key;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DataProtection: Cannot make masterKey from certificate {certName}", certName);
                throw;
            }
        }

        private static IAuthenticatedEncryptorDescriptor BuildEncryptorDescriptor(string secret)
        {
            byte[] secretBytes = System.Text.Encoding.UTF8.GetBytes(secret);
            var encryptorConfiguration = new AuthenticatedEncryptorConfiguration();

            return new AuthenticatedEncryptorDescriptor(encryptorConfiguration, new Secret(secretBytes));
        }

        private List<string> ValidateCertificate(KeyVaultCertificateWithPolicy cert)
        {
            var validationErrorsList = new List<string>();
            if (!cert.Properties.Enabled ?? false)
            {
                validationErrorsList.Add("Certificate must be in enabled state");
            }

            if (!cert.Properties.CreatedOn.HasValue)
            {
                string createdOnErrorMessage =
                    $"Certificate must not have null {nameof(cert.Properties.CreatedOn)} property";
                validationErrorsList.Add(createdOnErrorMessage);
            }

            if (!cert.Properties.ExpiresOn.HasValue)
            {
                string expresOnErrorMessage =
                    $"Certificate must not have null {nameof(cert.Properties.ExpiresOn)} property";
                validationErrorsList.Add(expresOnErrorMessage);
            }

            if (!cert.Properties.NotBefore.HasValue)
            {
                string notBeforeErrorMessage =
                    $"Certificate must not have null {nameof(cert.Properties.NotBefore)} property";
                validationErrorsList.Add(notBeforeErrorMessage);
            }

            string certVersionString = cert.Properties.Version;
            if (!Guid.TryParse(certVersionString, out Guid _))
            {
                validationErrorsList.Add($"Certificate have invalid version, cant parse it as {nameof(Guid)}");
            }

            return validationErrorsList;
        }

        private CertificateDescriptor ConvertToCertificateDescriptor(KeyVaultCertificateWithPolicy cert,
            string certSecret)
        {
            // creationDate and expirationDate and activationDate will always have it's values, because method ValidateCertificate checks this props
            DateTimeOffset creationDate = cert.Properties.CreatedOn.Value;
            DateTimeOffset expirationDate = cert.Properties.ExpiresOn.Value;
            DateTimeOffset activationDate = cert.Properties.NotBefore.Value;

            string certVersionString = cert.Properties.Version;
            var certVersion = Guid.Parse(certVersionString);

            return new CertificateDescriptor(certVersion, cert.Name, creationDate, expirationDate,
                activationDate, certSecret);
        }
    }
}
