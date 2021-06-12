/**
 * Contains only crypto operations representing each demo of the lab.
*/

const CRYPTO_OBJ = window.crypto;
//See https://developer.mozilla.org/en-US/docs/Web/API/TextDecoder
const decoder = new TextDecoder("utf8");

//Credits: https://stackoverflow.com/a/40031979/451455
function toHex(buffer) { 
    return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, "0")).join("");
}

function performRandomValuesGeneration(wantedLength){
    let buffer = new Int32Array(wantedLength);
    CRYPTO_OBJ.getRandomValues(buffer);
    return toHex(buffer);
}

