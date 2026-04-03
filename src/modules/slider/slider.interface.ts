export interface IImage {
    url: string;
    publicId: string;
}

export interface IActionButton {
    text: string;
    link: string;
}

export interface ISliderItem {
    title: string;
    description?: string;
    images: { url: string; publicId: string }[];
    actionButton?: { text: string; link: string };
    displayOrder: number;
    animationType: "fade" | "slide" | "zoom" | "none";
    isActive: boolean;
}

export type SliderItemResponse = ISliderItem;