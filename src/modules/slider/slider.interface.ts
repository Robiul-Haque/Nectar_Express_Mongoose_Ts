export interface IImage {
    _id?: string;
    url: string;
    publicId: string;
    displayOrder: number;
}

export interface IActionButton {
    text?: string;
    link?: string;
}

export interface ISlider {
    _id?: string;
    title: string;
    images: IImage[];
    actionButton?: IActionButton;
    animationType?: "fade" | "slide" | "zoom" | "none";
    isActive?: boolean;
    createdAt?: string;
    updatedAt?: string;
}