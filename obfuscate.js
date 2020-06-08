const obfuscate = require('./lib').obfuscate;

const options = {
    obfuscate: ['patient', 'birthdate', 'location', 'practitioner'],
    encryptionKey: {
        name: 'k01',
        value: '0123456789'
    }
};

const plaintexts = [
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?', 'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=xxx|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|abcdefg&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|4321654987&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=xxx|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|XXX&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|will@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=xxx&birthdate=1932-04-15',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=',
    'https://pyrusapps-dev.azurewebsites.net/esp/#!/launch?patient=https://fhir.nhs.uk/Id/nhs-number|9467335646&location=https://fhir.nhs.uk/Id/ods-organization-code|BPOPS&practitioner=https://sider.nhs.uk/auth|dunmail@blackpear.com&serviceId=654ce7d9-ee26-4934-d40c-71c5c32400c8&birthdate=xxx'
];

plaintexts
    .map((plaintext) => {
        const url = plaintext.split('?');

        if (!url[1]) {
            return plaintext;
        }

        return `${url[0]}?${obfuscate(url[1], options)}`;
    })
    .forEach((ciphertext) => {
        console.log(ciphertext);
    });
