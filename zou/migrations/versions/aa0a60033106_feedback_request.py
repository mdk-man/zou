"""Add is feedback request column to task types

Revision ID: aa0a60033106
Revises: 7b1f765677d8
Create Date: 2022-01-31 12:39:25.332258

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "aa0a60033106"
down_revision = "7b1f765677d8"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(
        "task_status",
        sa.Column("is_feedback_request", sa.Boolean(), nullable=True),
    )
    op.create_index(
        op.f("ix_task_status_is_feedback_request"),
        "task_status",
        ["is_feedback_request"],
        unique=False,
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(
        op.f("ix_task_status_is_feedback_request"), table_name="task_status"
    )
    op.drop_column("task_status", "is_feedback_request")
    # ### end Alembic commands ###
