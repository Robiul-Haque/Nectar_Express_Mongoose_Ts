import { Types } from "mongoose";

export interface IImage {
    url: string;
    publicId: string;
}

export interface IActionButton {
    text: string;
    link: string;
}

export interface ISlider {
    title: string;
    description?: string;
    images: {
        [x: string]: any; url: string; publicId: string 
}[];
    actionButton?: { text: string; link: string };
    displayOrder: number;
    animationType: "fade" | "slide" | "zoom" | "none";
    isActive: boolean;
}

export type SliderResponse = ISlider;