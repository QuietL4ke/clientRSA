
const rsa = require('js-crypto-rsa');
const aesjs = require('aes-js');
const ecdh = require('curve25519-js');
const rand = require('csprng');


(async () => {
    const URL = 'https://0e3c-46-56-243-194.eu.ngrok.io/';


    const keys = ecdh.generateKeyPair(Uint8Array.from(Buffer.from(rand(256, 16), 'hex')))

    const privateKey = keys.private;
    const publicKeyString = Buffer.from(keys.public).toString('hex');
    var sharedSecret;
    var key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    function sendSlash () {
        const XHRSlash = new XMLHttpRequest();
        XHRSlash.addEventListener('load', function (response) {
            if (response.target.status == 200) {
                const body = JSON.parse(response.target.response);
                const publicKeyServer = body.publicKey;
                sharedSecret = ecdh.sharedKey(privateKey, Uint8Array.from(Buffer.from(publicKeyServer, 'hex')));
                key = sharedSecret;
                localStorage.JWTEncryption = body.jwt;
                console.log(key)
            } else {
                console.log(response.target.status)
            }
        });
        XHRSlash.addEventListener('error', function (response) {
            console.log('??????????????????????????');
        });
        XHRSlash.open('POST', URL, true);
        XHRSlash.send(publicKeyString);    
    }

    sendSlash();

    function getRandomIV() {
        return Int16Array.from(Buffer.from(rand(128, 16), 'hex'));
    }

    function fixStrAes(str) {
        const tmpSimbols = str.length % 16;
        if (tmpSimbols !== 0) {
            return str + new Array(16 - tmpSimbols).fill(' ').join('');
        }
        return str;
    }

    function mapArray(data, isToStr) {
        if (isToStr) {
            return data.join(' ').split(' ').map(number => String.fromCharCode(number)).join('');
        } else {
            return new Int8Array(Array.from(data).map(el => el.charCodeAt(0)));
        }
    }

    function removeSpaces(str) {
        return str.substring(0, str.split('').findLastIndex(e => e !== ' ') + 1);
    }

    async function encryptMessage(data, isAes) {
        if (isAes) {
            const iv = getRandomIV();
            let str = JSON.stringify(data);
            const length = fixStrAes(String(str.length));
            str = length + str;
            const textBytes = aesjs.utils.utf8.toBytes(fixStrAes(str));
            const aesCbc = new aesjs.ModeOfOperation.cbc(key, Array.from(iv));
            var encryptedBytes = aesCbc.encrypt(textBytes);
            return Buffer.from(iv).toString('hex') + aesjs.utils.hex.fromBytes(encryptedBytes);
        } else {
            const int8 = mapArray(str, false);
            let encMessage = await rsa.encrypt(int8, publicKey, 'SHA-256');
            return mapArray(encMessage, true);
        }
    }

    async function decryptMessage(data, isAes) {
        if (isAes) {
            const iv = Array.from(Buffer.from(data.substring(0, 33), 'hex'));
            const str = data.substring(32, data.length);
            const encryptedBytes = aesjs.utils.hex.toBytes(str);
            const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
            const decryptedBytes = aesCbc.decrypt(encryptedBytes);
            const decStr = aesjs.utils.utf8.fromBytes(decryptedBytes);
            const length = removeSpaces(decStr.substring(0, 16));
            return decStr.substring(16, 16 + parseInt(length));
        } else {
            const int8 = mapArray(str, false);
            let decMessage = await rsa.decrypt(int8, privateKey, 'SHA-256');
            return mapArray(decMessage, true);
        }
    }

    // console.log(JSON.stringify({aboba: 'hui'}));
    // console.log(await decryptMessage(await encryptMessage({aboba: 'huasdasdsasdai'}, true), true));

    const header = document.getElementsByClassName('header')[0];
    const content = document.getElementsByClassName('section-content')[0];

    let filename = '';

    if (localStorage.JWT !== 'undefined') {
        closeLogin();
        openContent();
    }

    async function sendData(data, endpoint, type, onLoad, onError, jwt) {
        console.log('Sending data');
        const XHR = new XMLHttpRequest();
        XHR.addEventListener('load', onLoad);
        XHR.addEventListener('error', onError);
        XHR.open(type, URL + endpoint, true);
        if (jwt) {
            XHR.setRequestHeader('Authorization', 'Bearer ' + jwt);
        }
        if (type == "GET") {
            XHR.send();
        } else {
            XHR.send(await encryptMessage(JSON.stringify(data), true));
        }
    }

    function openContent() {
        content.classList.remove('display-none');
        header.classList.remove('display-none');
    }

    function closeContent() {
        content.classList.add('display-none');
        header.classList.add('display-none');
        document.getElementById('section-file').classList.add('display-none');
        document.getElementById('filename-input').value = "";
    }

    function openLogin() {
        const form = document.getElementById('form-login');
        form.classList.remove('display-none');
    }

    function closeLogin() {
        const form = document.getElementById('form-login');
        form.classList.add('display-none');
    }

    function isLogout(response) {
        if (response.target.status == 401) {
            closeContent();
            openLogin();
            localStorage.JWT = undefined;
        }
    }

    async function loginFormOnSubmit(e) {
        const emailInput = document.getElementById('email-login');
        const passInput = document.getElementById('password-login');
        closeLogin();
        function loginOnError(response) {
            alert('Something went wrong with server' + response);
            openLogin();
        }

        async function loginOnload(response) {
            if (response.currentTarget.status == 200) {
                openContent();
                const body = JSON.parse(await decryptMessage(response.currentTarget.response, true));
                document.getElementById('username').textContent = body.username;
                localStorage.JWT = body.token;
            } else loginOnError(response.currentTarget.status)
        }
        await sendData({ email: emailInput.value, password: passInput.value }, 'auth/login', 'POST', loginOnload, loginOnError, localStorage.JWTEncryption);
        e.preventDefault();
    }

    async function registerFormOnSubmit(e) {
        const emailInput = document.getElementById('email-register');
        const passInput = document.getElementById('password-register');
        const username = document.getElementById('username-register');
        const form = document.getElementById('form-register');
        form.classList.add('display-none');

        function registerOnError(response) {
            alert('Something went wrong with server' + response);
            form.classList.remove('display-none');
        }

        function registerOnload(response) {
            if (response.currentTarget.status == 200) {
                alert('Пользователь создан');
                document.getElementById('form-login').classList.remove('display-none');
            }
            else registerOnError(response.currentTarget.status);
        }
        await sendData({ email: emailInput.value, password: passInput.value, username: username.value }, 'auth/register', 'POST', registerOnload, registerOnError, localStorage.JWTEncryption);
        e.preventDefault();
    }

    function disableButtons(disable) {
        const buttons = document.getElementsByClassName('sections__file-buttons')[0].children;
        for (const button of buttons) {
            if (disable) button.setAttribute('disabled', "");
            else button.removeAttribute('disabled');
        }
    }

    async function buttonDeleteHandler(e) {
        disableButtons(true);
        function deleteFileOnLoad(response) {
            if (isLogout(response)) {
                return;
            }
            if (response.currentTarget.status == 200) {
                document.getElementById('section-file').classList.add('display-none');
                disableButtons(false);
            } else deleteFileOnError(response.currentTarget.status)
        }

        function deleteFileOnError(response) {
            alert('Something went wrong with server' + response);
            disableButtons(false);
        }

        await sendData({ filename: filename }, 'files', 'DELETE', deleteFileOnLoad, deleteFileOnError, localStorage.JWT);
    }

    async function buttonFindHandler(e) {
        const buttonFind = document.getElementById('submit-filename');
        buttonFind.setAttribute('disabled', '')
        async function findFileOnLoad(response) {
            if (isLogout(response)) {
                return;
            }
            if (response.currentTarget.status == 200) {
                const body = JSON.parse(await decryptMessage(response.currentTarget.response, true));
                document.getElementById('section-file').classList.remove('display-none');
                document.getElementById('textarea').value = body.text;
                document.getElementById('span-filename').textContent = body.filename;
                filename = body.filename
                buttonFind.removeAttribute('disabled');
            } else findFileOnError(response.currentTarget.status);
        }

        function findFileOnError(response) {
            alert('Something went wrong with server' + response);
            buttonFind.removeAttribute('disabled');
        }

        const filenameFind = document.getElementById('filename-input').value;

        await sendData({ filename: filenameFind }, 'files', 'POST', findFileOnLoad, findFileOnError, localStorage.JWT);
    }

    async function buttonSaveHandler(e) {
        disableButtons(true);

        function saveFileOnLoad(response) {
            if (isLogout(response)) {
                return;
            }
            if (response.currentTarget.status == 200) {
                alert("Все успешно сохранено");
                disableButtons(false);
            } else saveFileOnError(response.currentTarget.status)
        }

        function saveFileOnError(response) {
            alert('Something went wrong with server' + response);
            disableButtons(false);
        }

        const text = document.getElementById('textarea').value;
        await sendData({ text: text, filename: filename }, 'files', 'PATCH', saveFileOnLoad, saveFileOnError, localStorage.JWT);
    }

    function goToRegister() {
        document.getElementById('form-login').classList.add('display-none');
        document.getElementById('form-register').classList.remove('display-none');
    }

    function goToLogin() {
        document.getElementById('form-login').classList.remove('display-none');
        document.getElementById('form-register').classList.add('display-none');
    }

    function logout() {
        localStorage.JWT = undefined;
        closeContent();
        openLogin();
        sendSlash();
    }

    function setUpListeners() {
        const loginForm = document.getElementById('form-login');
        loginForm.addEventListener('submit', loginFormOnSubmit);

        const registerForm = document.getElementById('form-register');
        registerForm.addEventListener('submit', registerFormOnSubmit);

        const buttonDelete = document.getElementsByClassName('button-delete')[0];
        buttonDelete.addEventListener('click', buttonDeleteHandler);

        const buttonFind = document.getElementById('submit-filename');
        buttonFind.addEventListener('click', buttonFindHandler);

        const buttonSave = document.getElementsByClassName('button-save')[0];
        buttonSave.addEventListener('click', buttonSaveHandler);

        const loginLink = document.getElementById('create-account-link');
        loginLink.addEventListener('click', goToRegister)

        const registerLink = document.getElementById('register-account-link');
        registerLink.addEventListener('click', goToLogin);

        const buttonLogout = document.getElementById('button-logout');
        buttonLogout.addEventListener('click', logout);
    }
    setUpListeners();
})()