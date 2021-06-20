/**
 * Contains commons functions used to render the lab.
 */

const TESTS_VALUES_LENGTH = [10, 100, 1000, 10000, 100000, 1000000];
var CHART_OBJECT = null;

async function executeTest(testCaseId) {
    let results = new Map();
    let input, output, cryptoKey, cryptoKeyPair = null;
    let start, end = 0;
    for (const v of TESTS_VALUES_LENGTH) {
        start = performance.now();
        switch (testCaseId) {
            case 1: {
                input = v;
                output = performRandomValuesGeneration(input);
                break;
            }
            case 2: {
                input = "X".repeat(v);
                output = await performSha512Hash(input);
                break;
            }
            case 3: {
                input = "X".repeat(v);
                cryptoKey = await performSymmetricKeyGenerationForEncryptionDecryptionUsageWithAESGCM();
                output = await performEncryptionDecryptionWithAESGCM(input, cryptoKey);
                break;
            }
            case 4: {
                input = "X".repeat(v);
                cryptoKey = await performSecretGenerationForSignVerifyUsageWithHMAC();
                output = await performSignVerifyWithHMAC(input, cryptoKey);
                break;
            }
            case 5: {
                input = "X".repeat(v);
                cryptoKeyPair = await performAsymmetricKeyGenerationForEncryptionDecryptionUsageWithRSAOAEP();
                //For the test case above "100", the browser raise an operation specific error so we trap it.
                //This error is consitent because the amount of data is big for a asymmetric encryption operation.
                //Asymmetric encryption is targeted for a small data like the protection of a symmetric key during the exchange for later symmetric encryption operation.
                try {
                    output = await performEncryptionDecryptionWithRSAOAEP(input, cryptoKeyPair.publicKey, cryptoKeyPair.privateKey);
                } catch (error) {
                    output = "LENGTH_UNSUPPORTED";
                    console.warn("TEST CASE " + v + " FAILED: " + error);
                }
                break;
            }
            case 6: {
                //WARNING THIS TEST CASE WILL MDADE BROWSER UNSTABLE!!!!!!
                cryptoKeyPair = await performAsymmetricKeyGenerationForEncryptionDecryptionUsageWithRSAOAEP();
                output = performIdentificationOfContentLengthLimitForEncryptionWithRSAOAEP(cryptoKeyPair.publicKey);
                input = "X".repeat(output);
                break;
            }
            case 7: {
                input = "X".repeat(v);
                cryptoKeyPair = await performAsymmetricKeyGenerationForSignVerifyUsageWithECDSA();
                output = await performSignVerifyWithECDSA(input, cryptoKeyPair.publicKey, cryptoKeyPair.privateKey);
                break;
            }
            case 8: {
                input = "X".repeat(v);
                output = await performKeyDerivationFromPassword(v, input);
                break;
            }
            default:
                output = "UnsupportedTestCase";
        }
        end = performance.now();
        let processingDelay = (end - start).toFixed(4);
        results.set(v, {
            "Output": output,
            "Input": input,
            "ProcessingDelayInMS": (output === "LENGTH_UNSUPPORTED") ? -1 : processingDelay //Value -1 means unsupported test case
        });
    }
    console.info("TEST CASE RESULTS:")
    console.info(results);
    return results;
}

function renderTestResults() {
    //Get wanted test case
    let testCaseId = parseInt(document.getElementById("selectLab").value, 10);
    if (testCaseId == -1) {
        return;
    }
    //Adapt UI
    document.getElementById("divLoading").style.visibility = "visible";
    if (CHART_OBJECT != null) {
        CHART_OBJECT.destroy();
    }
    //Execute the test case asynchronously
    executeTest(testCaseId).then(resultsMap => {
        let chartValues = [];
        resultsMap.forEach(function (value, key) {
            chartValues.push(value.ProcessingDelayInMS)
        });
        let data = {
            labels: TESTS_VALUES_LENGTH,
            datasets: [{
                label: "Processing delay in ms (value -1 means unsupported test case)",
                backgroundColor: 'rgba(207, 226, 255, 1)',
                borderColor: 'rgba(207, 226, 255, 1)',
                data: chartValues
            }]
        };
        let config = {
            type: "bar",
            data,
            options: {
                scales: {
                    y: {
                        title: {
                            display: true,
                            text: "Time taken in milliseconds."
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: "Test values length."
                        }
                    }
                }
            }
        };
        CHART_OBJECT = new Chart(
            document.getElementById("renderingTestResultsZone"), config
        );
        document.getElementById("divLoading").style.visibility = "hidden";
    }).catch(err => alert("ERROR: " + err));
}

function exportKey(mode) {
    switch (mode) {
        case "INSECURE": {
            performKeyExportUsingUnprotectedWay().then(key => {
                alert("Unprotected key encoded in HEX, use the CyberChef link to test it: " + key);
            }).catch(err => alert("ERROR: " + err));
            break;
        }
        case "SECURE": {
            let basePassword = prompt("Please enter the password to use to derivate a protection key", "AppSec@Excellium");
            performKeyExportUsingProtectedWay(basePassword).then(key => {
                alert("Protected key encoded in HEX, use the CyberChef link to test it: " + key);
            }).catch(err => alert("ERROR: " + err));
            break;
        }
        case "NON-EXTRACTABLE": {
            performKeyExportMarkedAsNonExtractable().then(key => {
                alert("Unprotected key encoded in HEX, use the CyberChef link to test it: " + key);
            }).catch(err => alert("ERROR: " + err));
            break;
        }
        default:
            alert("Unsupported mode!");
    }
}

function renderInit() {
    document.getElementById("divLoading").style.visibility = "hidden";
}