export class CopyButton extends HTMLElement {
    constructor() {
        super(...arguments);
        // Attribute storage
        this._elementId = null;
    }
    // Observe 'element-id' attribute
    static get observedAttributes() {
        return ["element-id"];
    }
    // Getter for 'element-id' property
    get elementId() {
        return this._elementId;
    }
    // Setter for 'element-id' property
    set elementId(value) {
        this._elementId = value;
        if (value) {
            this.setAttribute("element-id", value); // Reflect to HTML attribute
        }
        else {
            this.removeAttribute("element-id");
        }
    }
    // Fires when the element is added to the DOM
    connectedCallback() {
        const template = document.createElement("template");
        template.innerHTML = `
            <style>
                button {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 6px;
                    background: linear-gradient(135deg, #5D5FEF, #9845E8);
                    color: #FFF;
                    font-family: 'Roboto', sans-serif;
                    font-size: 12px;
                    font-weight: bold;
                    cursor: pointer;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
                    transition: transform 0.2s ease, background 0.2s ease;
                }
        
                button:hover {
                    background: linear-gradient(135deg, #6A6FF9, #A055F9);
                    transform: translateY(-2px);
                    box-shadow: 0 6px 8px rgba(0, 0, 0, 0.25);
                }
                
                button:active {
                    transform: translateY(0);
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
                }
                
                svg {
                    width: 16px;
                    height: 16px;
                    fill: white; /* Match icon color to text color */
                }

            </style>
            <button>
                <slot>
                <!-- Default Copy Icon -->
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                        <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                    </svg>
                    Copy
                </slot>
            </button>
        `;
        const shadow = this.attachShadow({ mode: "open" });
        shadow.appendChild(template.content.cloneNode(true));
        const button = shadow.querySelector("button");
        button === null || button === void 0 ? void 0 : button.addEventListener("click", this.copyTextFromElement.bind(this));
    }
    /**
     * Called when an observed attribute changes.
     */
    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "element-id") {
            this._elementId = newValue;
        }
    }
    /**
     * Copies the text content of the target element to the clipboard.
     */
    copyTextFromElement() {
        var _a;
        const elementId = this.elementId;
        if (!elementId) {
            console.error("Attribute 'element-id' is required.");
            return;
        }
        const targetElement = document.getElementById(elementId);
        if (targetElement) {
            const textToCopy = ((_a = targetElement.textContent) === null || _a === void 0 ? void 0 : _a.trim()) || "";
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    alert(`Copied: "${textToCopy}"`);
                });
            }
            else {
                console.error("The target element has no text content to copy.");
            }
        }
        else {
            console.error(`No element found with id "${elementId}".`);
        }
    }
}
// Define the custom element
customElements.define("copy-button", CopyButton);
