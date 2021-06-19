/**
 * Contains commons functions used to render the lab.
 */

const TESTS_VALUES_LENGTH = [10, 100, 1000, 10000, 100000, 1000000];

async function executeTest(testCaseId) {
    let results = new Map();
    let input, output = null;
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
            default:
                output = "Unsupported!";
        }
        end = performance.now();
        results.set(v, {
            "Output": output,
            "Input": input,
            "ProcessingDelayInMS": (output === "LENGTH_UNSUPPORTED") ? -1 : (end - start).toFixed(4) //Value -1 means unsupported test case
        });
    }
    console.info("TEST CASE RESULTS:")
    console.info(results);
    return results;
}

function renderTestResults(testCaseId) {
    executeTest(testCaseId).then(resultsMap => {
        let chartValues = [];
        resultsMap.forEach(function (value, key) {
            chartValues.push(value.ProcessingDelayInMS)
        });
        let data = {
            labels: TESTS_VALUES_LENGTH,
            datasets: [{
                label: "Processing delay in ms (value -1 means unsupported test case)",
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 0.2)',
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
        new Chart(
            document.getElementById("renderingTestResultsZone"), config
        );
    }).catch(err => alert("ERROR: " + err));
}