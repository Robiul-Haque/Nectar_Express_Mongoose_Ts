export interface IImage {
    url: string;
    publicId: string;
}

export interface IActionButton {
    text: string;
    link: string;
}

export interface ISliderItem {
    _id: string;
    title: string;
    description?: string;
    image: IImage;
    actionButton?: IActionButton;
    displayOrder: number;
    animationType: "fade" | "slide" | "zoom" | "none";
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
}

export type SliderItemResponse = ISliderItem;