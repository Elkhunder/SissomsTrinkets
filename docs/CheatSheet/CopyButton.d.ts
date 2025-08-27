export declare class CopyButton extends HTMLElement {
    static get observedAttributes(): string[];
    private _elementId;
    get elementId(): string | null;
    set elementId(value: string | null);
    connectedCallback(): void;
    /**
     * Called when an observed attribute changes.
     */
    attributeChangedCallback(name: string, oldValue: string | null, newValue: string | null): void;
    /**
     * Copies the text content of the target element to the clipboard.
     */
    private copyTextFromElement;
}
