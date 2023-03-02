// *
// @uthor Manas
// *

const express = require('express');
const cors = require("cors");
const dotenv = require('dotenv')
const { loggerUtil } = require('./utils/logger');
const app = express();
const bodyParser = require("body-parser");
const formidable = require('formidable')

// Setting Up App to use data from .env file
dotenv.config()

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(bodyParser.json());
app.use(express.static(__dirname));


const docusign = require("docusign-esign")
const jwtConfig = require('./jwtConfig.json');
const fs = require("fs")
const path = require('path');

const demoDocsPath = path.resolve(__dirname, '../demo_documents');
const doc1 = "Corporation PPM SWOG Find IV.pdf"
const doc2 = "Individual PPM SWOG Find IV.pdf"
const doc3 = "Individual_twith_ag.pdf"
const doc4 = "IRA or Keough PPM SWOG Find IV.pdf"
const doc5 = "Partnership PPM SWOG Find IV.pdf"
const doc6 = "Trust PPM SWOG Fund IV.pdf"

const SCOPES = [
    "signature", "impersonation"
];


async function authenticate() {
    const jwtLifeSec = 10 * 60, // requested lifetime for the JWT is 10 min
        dsApi = new docusign.ApiClient();
    dsApi.setOAuthBasePath(jwtConfig.dsOauthServer.replace('https://', '')); // it should be domain only.
    let rsaKey = fs.readFileSync(jwtConfig.privateKeyLocation);

    try {
        const results = await dsApi.requestJWTUserToken(jwtConfig.dsJWTClientId,
            jwtConfig.impersonatedUserGuid, SCOPES, rsaKey,
            jwtLifeSec);
        const accessToken = results.body.access_token;

        // get user info
        const userInfoResults = await dsApi.getUserInfo(accessToken);

        // use the default account
        let userInfo = userInfoResults.accounts.find(account =>
            account.isDefault === "true");

        return {
            accessToken: results.body.access_token,
            apiAccountId: userInfo.accountId,
            basePath: `${userInfo.baseUri}/restapi`
        };
    } catch (e) {
        console.log(e);
        let body = e.response && e.response.body;
        // Determine the source of the error
        if (body) {
            this._debug_log(`\nAPI problem: Status code ${e.response.status}, message body:
              ${JSON.stringify(body, null, 4)}\n\n`);
        }
    }
}

function getArgs(apiAccountId, accessToken, basePath, signerEmail, signerName, ccEmail, ccName, userId, doc) {
    let uploadDoc;
    switch (doc.toString()) {
        case "1":
            uploadDoc = path.resolve(demoDocsPath, doc1)
            break
        case "2":
            uploadDoc = path.resolve(demoDocsPath, doc2)
            break
        case "3":
            uploadDoc = path.resolve(demoDocsPath, doc3)
            break
        case "4":
            uploadDoc = path.resolve(demoDocsPath, doc4)
            break
        case "5":
            uploadDoc = path.resolve(demoDocsPath, doc5)
            break
        case "6":
            uploadDoc = path.resolve(demoDocsPath, doc6)
            break
        default:
            uploadDoc = path.resolve(demoDocsPath, doc1)
            break;

    }
    const envelopeDefinition = new docusign.EnvelopeDefinition();
    envelopeDefinition.emailSubject = 'Please sign this document';
    envelopeDefinition.documents = [{
        documentBase64: fs.readFileSync(uploadDoc, "base64"),
        name: 'My Document.pdf',
        documentId: '1'
    }];
    envelopeDefinition.recipients = {
        signers: [{
            email: signerEmail,
            name: signerName,
            recipientId: userId,
            clientUserId: userId,
            tabs: {
                signHereTabs: [{
                    anchorString: '/sign_here/',
                }]
            }
        }]
    };
    envelopeDefinition.status = 'sent';
    envelopeDefinition.returnUrl = ""

    const args = {
        accessToken: accessToken,
        basePath: basePath,
        accountId: apiAccountId,
        envelopeArgs: envelopeDefinition
    };

    return args
}


async function main(req, res) {
    try {
        const form = new formidable.IncomingForm()
        form.parse(req, async (err, fields, file) => {
            if (err) {
                loggerUtil(err, 'ERROR')
                return res.status(SC.BAD_REQUEST).json({
                    error: 'Problem with a file!'
                })
            }
            // if (file.doc.size > 3000000) {
            //     return res.status(SC.BAD_REQUEST).json({
            //         error: 'File size is too big!'
            //     })
            // } else {
            let accountInfo = await authenticate();

            // const pathVal = file.doc.path
            // const doc = fs.readFileSync(pathVal, "base64")

            let args = getArgs(accountInfo.apiAccountId, accountInfo.accessToken, accountInfo.basePath, fields.email.toString(), fields.userName, "", "", fields.userId, fields.doc);
            const dsApiClient = new docusign.ApiClient();
            dsApiClient.setBasePath('https://demo.docusign.net/restapi');
            dsApiClient.addDefaultHeader('Authorization', 'Bearer ' + args.accessToken);
            const envelopesApi = new docusign.EnvelopesApi(dsApiClient);

            const envelopeSummary = await envelopesApi.createEnvelope(args.accountId, { envelopeDefinition: args.envelopeArgs });

            let recipientViewRequest = new docusign.RecipientViewRequest();
            recipientViewRequest.authenticationMethod = 'Email';
            recipientViewRequest.email = fields.email.toString();
            recipientViewRequest.userName = fields.userName.toString();
            recipientViewRequest.returnUrl = fields.redirectUrl;
            recipientViewRequest.clientUserId = fields.userId; // must be unique per recipient

            envelopesApi.createRecipientView(args.accountId, envelopeSummary.envelopeId, { recipientViewRequest: recipientViewRequest })
                .then((result) => {
                    res.status(200).json({
                        status: 200,
                        url: result.url,
                        fields: fields
                    })
                })
                .catch((error) => {
                    res.status(400).json({
                        status: 400,
                        error: error
                    })
                });
            // }
        })

    }
    catch (err) {
        res.status(400).json({
            "status": 400,
            err: err
        })
    }

}

app.post("/docusign-api", main)


app.listen(8002, () => loggerUtil(`Server running on port: 8002`))
