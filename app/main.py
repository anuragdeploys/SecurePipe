from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import models
from .database import Base, engine, get_db


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="SecurePipe",
    description="Sample application protected by the SecurePipe DevSecOps pipeline.",
    version="1.0.0",
)


class ItemCreate(BaseModel):
    name: str
    description: str | None = None


class ItemResponse(BaseModel):
    id: int
    name: str
    description: str | None = None

    class Config:
        from_attributes = True


@app.get("/")
def root():
    return {
        "application": "SecurePipe",
        "status": "running",
        "version": "1.0.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


@app.post("/items/", response_model=ItemResponse)
def create_item(
    item: ItemCreate,
    db: Session = Depends(get_db),
):
    db_item = models.Item(
        name=item.name,
        description=item.description,
    )

    db.add(db_item)
    db.commit()
    db.refresh(db_item)

    return db_item


@app.get("/items/", response_model=list[ItemResponse])
def list_items(
    db: Session = Depends(get_db),
):
    return db.query(models.Item).all()


@app.get("/items/{item_id}", response_model=ItemResponse)
def get_item(
    item_id: int,
    db: Session = Depends(get_db),
):
    item = (
        db.query(models.Item)
        .filter(models.Item.id == item_id)
        .first()
    )

    if item is None:
        raise HTTPException(
            status_code=404,
            detail="Item not found",
        )

    return item
